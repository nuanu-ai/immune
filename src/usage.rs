//! What Immunity Core says about its own command line: `immunity --help`, the full form of one command
//! (`immunity help <command>`, `immunity <command> --help`), and a misuse, told as an error with the
//! right form of the command the person typed.
//!
//! What is adopted, from the common practice of mature command-line tools (clig.dev, rustc's
//! diagnostics, git, cargo): the help opens with what the program is and what to run first; the
//! commands are grouped and each has one line; flags only tests pass are left to the reference;
//! a misuse is a short error with the cause and the right form, never the whole usage.
//!
//! The commands of the binary are `COMMANDS`, and the parser takes no other (`main::parse_args`),
//! so a command cannot be added without its line here.
//!
//! The help is Immunity Core's own text and holds nothing from a source. A misuse shows what the
//! person typed in its right form: each word they gave is cut of secrets and escaped
//! (`secrets::said`), and the line is one command, never read as marks.

use crate::screen::{BOLD, CYAN, Screen, Step, columns};

/// One command of the binary: its name, its purpose in a few words, its forms, each a list of
/// words that are not broken apart, and what it does, in a few sentences, for its own help.
pub struct Command {
    pub name: &'static str,
    pub purpose: &'static str,
    forms: &'static [&'static [&'static str]],
    about: &'static str,
    /// Words the command's help ends with that other answers carry too, the same words.
    note: &'static str,
}

/// Every command of the binary, in the order the help lists them.
pub const COMMANDS: &[Command] = &[
    Command {
        name: "status",
        purpose: "what needs a look, and what was not judged",
        forms: &[&[
            "immunity status",
            "[--coverage]",
            "[--store <path>]",
            "[--json | --proto]",
        ]],
        about: "What the last finished check left, read without writing. --coverage shows \
                what was read and what was not, whole.",
        note: "",
    },
    Command {
        name: "findings",
        purpose: "the open findings, the most urgent first",
        forms: &[&[
            "immunity findings",
            "[--all]",
            "[--store <path>]",
            "[--json | --proto]",
        ]],
        about: "The open findings, the most urgent first; --all lists every finding, \
                answered and cleared ones too. --json and --proto always give every finding.",
        note: "",
    },
    Command {
        name: "finding",
        purpose: "one finding whole, or an answer to it",
        forms: &[
            &[
                "immunity finding <id>",
                "[--store <path>]",
                "[--json | --proto]",
            ],
            &[
                "immunity finding <id> expected",
                "--reason <text>",
                "[--days <n>]",
                "[--via app|agent]",
                "[--with <id>]",
                "[--journal-seq <n>]",
                "[--store <path>]",
                "[--json | --proto]",
            ],
            &[
                "immunity finding <id> seen",
                "[--reason <text>]",
                "[--via app|agent]",
                "[--with <id>]",
                "[--journal-seq <n>]",
                "[--store <path>]",
                "[--json | --proto]",
            ],
            &[
                "immunity finding <id> reopen",
                "[--via app|agent]",
                "[--with <id>]",
                "[--journal-seq <n>]",
                "[--store <path>]",
                "[--json | --proto]",
            ],
        ],
        about: "One finding whole: its words, evidence, journal entries and answer. expected \
                takes it out of what needs a look for 30 days, or --days. seen closes it; if it \
                happens again, a new finding opens. reopen takes an answer back. Each answers \
                with the finding as it left it. --with gives the same answer to the other \
                finding of a pair, or, once for each, to other findings of one group, in one \
                transaction. --journal-seq names the answer the \
                findings were read in; the answer is refused if anything joined them since, and \
                it is needed with --with, --via agent or --via app. --via says who gave the \
                answer; without it, the command line.",
        note: crate::findings::ANSWERS_NOTE,
    },
    Command {
        name: "project",
        purpose: "what Immunity Core knows of one project",
        forms: &[&[
            "immunity project <path or id>",
            "[--store <path>]",
            "[--json | --proto]",
        ]],
        about: "What the store knows of one project: its facts, what was read and what was \
                not, and its findings. The path is absolute, begins with ~/ or is relative to \
                the folder the command is started in, so . is that folder.",
        note: "",
    },
    Command {
        name: "program",
        purpose: "the same for an installed program",
        forms: &[&[
            "immunity program <path, name or id>",
            "[--store <path>]",
            "[--json | --proto]",
        ]],
        about: "The same for one program installed on this Mac: an application, a Homebrew \
                package or keg, a global npm package.",
        note: "",
    },
    Command {
        name: "machine",
        purpose: "the same for this Mac or another machine",
        forms: &[&[
            "immunity machine",
            "[<name or id>]",
            "[--store <path>]",
            "[--json | --proto]",
        ]],
        about: "The same for this Mac, or for another machine the store knows, with its parts \
                one level deep.",
        note: "",
    },
    Command {
        name: "rules",
        purpose: "the published rules and what they matched",
        forms: &[
            &[
                "immunity rules",
                "[--all]",
                "[--store <path>]",
                "[--json | --proto]",
            ],
            &[
                "immunity rules --over-log",
                "[--system-root <dir>]",
                "[--json | --proto]",
            ],
        ],
        about: "The shipped rules for macOS: which are evaluated on every program start, \
                which in part and which not, with the reason, and how many times each matched \
                in the last day and week. Its text is a summary; --all lists every rule. \
                --over-log evaluates them over the event log on disk now, without the store, \
                and gives each rule that matched with its count.",
        note: "",
    },
    Command {
        name: "vulnerabilities",
        purpose: "known vulnerabilities in your projects",
        forms: &[&[
            "immunity vulnerabilities",
            "[--store <path>]",
            "[--json | --proto]",
        ]],
        about: "Known vulnerabilities that affect packages the projects' lockfiles declare.",
        note: "",
    },
    Command {
        name: "vulnerability",
        purpose: "one vulnerability in every project",
        forms: &[&[
            "immunity vulnerability <record id or CVE id>",
            "[--store <path>]",
            "[--json | --proto]",
        ]],
        about: "The answer for one vulnerability in every project, with what it rests on.",
        note: "",
    },
    Command {
        name: "servers",
        purpose: "lists known servers, writes the sweep script",
        forms: &[&[
            "immunity servers",
            "[--store <path>]",
            "[--tailscale <path>]",
        ]],
        about: "The servers this Mac knows, and the read-only sweep script for you to run. \
                Immunity Core itself never connects to a server.",
        note: "",
    },
    Command {
        name: "owner",
        purpose: "machines set aside as retired or not yours",
        forms: &[
            &[
                "immunity owner",
                "[--store <path>]",
                "[--tailscale <path>]",
                "[--json | --proto]",
            ],
            &[
                "immunity owner <name> retired|not-mine",
                "--reason <text>",
                "[--via app|agent]",
                "[--store <path>]",
                "[--tailscale <path>]",
                "[--json | --proto]",
            ],
            &[
                "immunity owner <name> withdraw",
                "[--via app|agent]",
                "[--store <path>]",
                "[--tailscale <path>]",
                "[--json | --proto]",
            ],
        ],
        about: "Alone, the machines set aside. retired and not-mine set a machine aside, so \
                it is no longer checked; withdraw takes that back. --via says who said it; \
                without it, the command line. An agent says it only after the person has said \
                so in the conversation, with --via agent and their reason.",
        note: "",
    },
    Command {
        name: "matches",
        purpose: "every rule match, with the event it matched",
        forms: &[&[
            "immunity matches",
            "[--after <place>]",
            "[--limit <n>]",
            "[--store <path>]",
            "[--system-root <dir>]",
            "[--json | --proto]",
        ]],
        about: "Every rule match over the event log, of every level, each with the event it \
                matched; what was read, lost and not evaluated; and the place to read on from \
                with --after.",
        note: "",
    },
    Command {
        name: "verdict",
        purpose: "records a verdict read on standard input",
        forms: &[&[
            "immunity verdict",
            "(--json | --proto)",
            "[--store <path>]",
            "[--system-root <dir>]",
        ]],
        about: "Records the response layer's verdict about a match or a finding: one Verdict \
                message on standard input, binary with --proto or JSON with --json, answered in \
                the same form. A verdict never closes or quiets a finding.",
        note: "",
    },
    Command {
        name: "watch",
        purpose: "watches; one JSON line per event",
        forms: &[&[
            "immunity watch",
            "[--store <path>]",
            "[--system-root <dir>]",
            "[--sample-input <file>]",
            "[--sample-every <seconds>]",
            "[--events-every <seconds>]",
            "[--alive-every <seconds>]",
            "[--standalone | --background]",
        ]],
        about: "Runs until stopped and prints one JSON line per event: watching, read, sample, \
                program_starts, alive, problem. --standalone goes on after its parent exits; \
                --background also runs a full check at start and every hour. It exits with 5 \
                when another watcher has the store.",
        note: "",
    },
    Command {
        name: "on",
        purpose: "runs checks in the background",
        forms: &[&[
            "immunity on",
            "[--launchctl <path> --home <dir>]",
            "[--json | --proto]",
        ]],
        about: "Turn Immunity Core on for your account: the background check starts and keeps \
                running. Registers the core as your login job ai.nuanu.immunity.core.watch, which runs immunity \
                watch --background, and says whether it started. A core only root can replace \
                is run where it is; any other, such as a build, is copied to \
                ~/Library/Application Support/ai.nuanu.immunity.core/bin/immunity and the job runs the \
                copy. Run it again from a new build to update. Run it as the user being \
                watched, without sudo. --launchctl and --home are for tests and go together.",
        note: "",
    },
    Command {
        name: "off",
        purpose: "stops that; keeps the store",
        forms: &[&[
            "immunity off",
            "[--launchctl <path> --home <dir>]",
            "[--json | --proto]",
        ]],
        about: "Turn Immunity Core off for your account. The store, findings and answers are kept. \
                Stops the login job and removes it with the copy of the core; a core run where \
                it is stays. The event collector is kept too.",
        note: "",
    },
    Command {
        name: "run",
        purpose: "one full check now",
        forms: &[&[
            "immunity run",
            "[--store <path>]",
            "[--machine-name <name>]",
            "[--brew <path>]",
            "[--brew-input <file>]",
            "[--servers-input <dir>]",
            "[--checkouts-root <dir>]",
            "[--sessions-root <dir>]",
            "[--tailscale <path>]",
            "[--threats-input <file>]",
            "[--osv-crates-input <file>]",
            "[--osv-npm-input <file>]",
            "[--curl <path>]",
            "[--system-root <dir>]",
            "[--indicators <file>]",
            "[--json | --proto]",
        ]],
        about: "One full check now; with --json or --proto it answers as immunity status does. \
                The flags after --store are for tests and special cases, and docs/reference.md \
                describes each.",
        note: "",
    },
    Command {
        name: "sample",
        purpose: "one sample of processes and connections",
        forms: &[&[
            "immunity sample",
            "[--store <path>]",
            "[--sample-input <file>]",
            "[--json | --proto]",
        ]],
        about: "One sample of this user's processes and their connections.",
        note: "",
    },
    Command {
        name: "view",
        purpose: "writes the pages and opens the summary",
        forms: &[&[
            "immunity view",
            "[--store <path>]",
            "[--no-open]",
            "[--if-stale]",
        ]],
        about: "Writes every page and prints their paths, the summary first. With --if-stale \
                it writes only when something they show changed, or they are an hour old.",
        note: "",
    },
];

/// Whether `name` is a command of the binary.
pub fn is_command(name: &str) -> bool {
    COMMANDS.iter().any(|c| c.name == name)
}

/// One line of the help: a command with its main arguments, and what it does.
type Entry = (&'static str, &'static str);

/// The groups of the help, each with its label and its lines.
const GROUPS: &[(&str, &[Entry])] = &[
    (
        "See what needs a look",
        &[
            (
                "immunity status [--coverage]",
                "what needs a look, and what was not judged",
            ),
            (
                "immunity findings [--all]",
                "the open findings, the most urgent first",
            ),
            (
                "immunity finding <id>",
                "one finding whole, with its evidence",
            ),
        ],
    ),
    (
        "Answer a finding",
        &[
            (
                "immunity finding <id> expected --reason <text> [--days <n>]",
                "out of what needs a look for 30 days or <n>",
            ),
            (
                "immunity finding <id> seen [--reason <text>]",
                "closes it; a new occurrence opens a new one",
            ),
            ("immunity finding <id> reopen", "takes an answer back"),
        ],
    ),
    (
        "Ask about a project, a program, a machine",
        &[
            (
                "immunity project <path or id>",
                "what Immunity Core knows of one project",
            ),
            (
                "immunity program <path, name or id>",
                "the same for an installed program",
            ),
            (
                "immunity machine [<name or id>]",
                "the same for this Mac or another machine",
            ),
        ],
    ),
    (
        "What Immunity Core looks for",
        &[
            (
                "immunity rules [--all | --over-log]",
                "the published rules and what they matched",
            ),
            (
                "immunity vulnerabilities",
                "known vulnerabilities in your projects",
            ),
            (
                "immunity vulnerability <id>",
                "one vulnerability in every project",
            ),
        ],
    ),
    (
        "Servers",
        &[
            (
                "immunity servers",
                "lists known servers, writes the sweep script",
            ),
            ("immunity owner", "the machines set aside"),
            (
                "immunity owner <name> retired|not-mine --reason <text>",
                "sets a machine aside",
            ),
            ("immunity owner <name> withdraw", "takes that back"),
        ],
    ),
    (
        "For the response layer",
        &[
            (
                "immunity matches [--after <place>] [--limit <n>]",
                "every rule match, with the event it matched",
            ),
            (
                "immunity verdict (--json | --proto)",
                "records a verdict read on standard input",
            ),
            ("immunity watch", "watches; one JSON line per event"),
        ],
    ),
    (
        "Setup",
        &[
            ("immunity on", "runs checks in the background"),
            ("immunity off", "stops that; keeps the store"),
            ("immunity run", "one full check now"),
            ("immunity sample", "one sample of processes and connections"),
            (
                "immunity view [--no-open] [--if-stale]",
                "writes the pages and opens the summary",
            ),
        ],
    ),
];

/// The column a line of the help says what its command does in.
const DOES_AT: usize = 36;

/// `immunity --help`: what Immunity Core is and what to run first, then the commands in groups, one line
/// each, then the forms of an answer and where the rest is described. No line is wider than 80
/// columns. On a terminal commands are cyan and the labels bold; in a pipe it is plain.
pub fn help(screen: &Screen) -> String {
    let mut out: Vec<String> = Vec::new();
    out.extend(screen.marked(
        "Immunity Core watches this Mac for signs of attack and says what needs a look.",
        None,
    ));
    out.extend(screen.marked(
        "Start with `immunity on`, then `immunity status` and `immunity findings`.",
        None,
    ));
    for (label, entries) in GROUPS {
        out.push(String::new());
        out.push(screen.paint(BOLD, label));
        for (command, does) in *entries {
            out.extend(entry(screen, command, does));
        }
    }
    out.push(String::new());
    for line in [
        "Every command but `immunity servers`, `immunity view` and `immunity watch` answers in",
        "text, as JSON with --json, or as binary protobuf with --proto.",
        "Every command takes --store <path>. `immunity help <command>` shows all the flags",
        "of one; the flags for tests are described in docs/reference.md.",
    ] {
        out.extend(screen.marked(line, None));
    }
    lines(&out)
}

/// One line of the help: the command cyan after two spaces, what it does from `DOES_AT`; a
/// command too long for that goes on a line of its own.
fn entry(screen: &Screen, command: &str, does: &str) -> Vec<String> {
    let painted = format!("  {}", screen.paint(CYAN, command));
    let used = 2 + columns(command);
    if used + 2 <= DOES_AT {
        vec![format!("{painted}{}{does}", " ".repeat(DOES_AT - used))]
    } else {
        vec![painted, format!("{}{does}", " ".repeat(DOES_AT))]
    }
}

/// `immunity help <command>` and `immunity <command> --help`: every form of one command with every
/// flag, cyan on a terminal, then what it does. `None` for a name that is no command.
pub fn command_help(name: &str, screen: &Screen) -> Option<String> {
    let c = COMMANDS.iter().find(|c| c.name == name)?;
    let mut out: Vec<String> = Vec::new();
    for form in c.forms {
        out.extend(
            form_lines(form)
                .iter()
                .map(|l| screen.paint(CYAN, l.trim_end())),
        );
    }
    out.push(String::new());
    let about = [c.about, c.note].join(" ");
    out.extend(
        screen
            .marked(about.trim_end(), Some(78))
            .into_iter()
            .map(|l| format!("  {l}")),
    );
    Some(lines(&out))
}

/// A form's words in lines of at most 80 columns, a word never broken, each line after the
/// first indented under the first word's end, as a manual page sets a synopsis.
fn form_lines(form: &[&str]) -> Vec<String> {
    let hang = form.first().map_or(0, |w| columns(w) + 1);
    let mut out: Vec<String> = Vec::new();
    let mut line = String::new();
    for word in form {
        if !line.is_empty() && columns(&line) + 1 + columns(word) > 80 {
            out.push(std::mem::take(&mut line));
            line = " ".repeat(hang);
        } else if !line.is_empty() && !line.ends_with(' ') {
            line.push(' ');
        }
        line.push_str(word);
    }
    out.push(line);
    out
}

fn lines(out: &[String]) -> String {
    out.iter().map(|l| format!("{l}\n")).collect()
}

/// No command, or a word that is not one: the error, every command in one line with its
/// purpose, and where each is told whole. `asked` is the word as typed.
pub fn unknown(asked: Option<&str>, screen: &Screen) -> String {
    let cause = match asked {
        None => "immunity needs a command".to_string(),
        Some(word) => format!(
            "{} is not a command of immunity",
            crate::text::quoted(&crate::secrets::said(word))
        ),
    };
    let mut out = screen.error(&cause, &[], &[]);
    let width = COMMANDS
        .iter()
        .map(|c| columns(c.name) + 7)
        .max()
        .unwrap_or(0);
    for c in COMMANDS {
        let command = format!("immunity {}", c.name);
        out.push_str(&format!(
            "  {}{}{}\n",
            screen.paint(CYAN, &command),
            " ".repeat(width + 2 - columns(&command)),
            c.purpose
        ));
    }
    for l in screen.marked(
        "`immunity --help` shows each with its arguments.",
        screen.fits(),
    ) {
        out.push_str(&format!("  {l}\n"));
    }
    out
}

/// A misuse of `op`, told to a person: the cause in Immunity Core's words, then the command as typed in
/// its right form, the person's own values kept and the missing part shown as a placeholder
/// (`right_form`). `args` are the words after the command; `said` is what the parser said.
pub fn misuse(op: &str, args: &[String], said: &str, screen: &Screen) -> String {
    let (cause, form) = right_form(op, args, said);
    screen.error(&cause, &form.steps(), &[])
}

/// A command Immunity Core prints for a person to paste, made from what was typed: every word typed is
/// either in it exactly as typed (`text::shell_word`) or, where it cannot be shown exactly, its
/// placeholder; and then the sentence that says which were left out.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pasted {
    pub command: String,
    pub left_out: Option<String>,
}

impl Pasted {
    /// A command made only of Immunity Core's own words.
    pub fn own(command: &str) -> Pasted {
        Pasted {
            command: command.to_string(),
            left_out: None,
        }
    }

    /// The command, and the sentence about what was left out, as steps of an error.
    pub fn steps(&self) -> Vec<Step> {
        let mut steps = vec![Step::Command(self.command.clone())];
        steps.extend(self.left_out.clone().map(Step::Words));
        steps
    }
}

/// The placeholder of the `n`th operand of `op`, from the first of its forms: `<id>`, `<path or
/// id>`; `<value>` where the form names none.
fn operand_placeholder(op: &str, n: usize) -> &'static str {
    let Some(form) = COMMANDS
        .iter()
        .find(|c| c.name == op)
        .map(|c| c.forms[0][0])
    else {
        return "<value>";
    };
    let mut rest = form;
    let mut found = Vec::new();
    while let Some(at) = rest.find('<') {
        let end = rest[at..].find('>').map_or(rest.len(), |e| at + e + 1);
        found.push(&rest[at..end]);
        rest = &rest[end..];
    }
    found.get(n).copied().unwrap_or("<value>")
}

/// The flags a form of a command takes, as its help lists them: `--via` of `[--via app|agent]`.
fn form_flags(op: &str, verb: Option<&str>) -> Vec<&'static str> {
    let Some(c) = COMMANDS.iter().find(|c| c.name == op) else {
        return Vec::new();
    };
    let form = c
        .forms
        .iter()
        .find(|f| verb.is_none_or(|v| f[0].split(' ').skip(2).any(|w| w == v)))
        .unwrap_or(&c.forms[0]);
    form.iter()
        .skip(1)
        .flat_map(|part| part.trim_matches(['[', ']']).split(" | "))
        .filter_map(|part| part.split(' ').next())
        .filter(|w| w.starts_with("--"))
        .collect()
}

/// What a word of a command line is to the parser: an operand, the `n`th; a flag; or the value
/// of the flag named.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Role<'a> {
    Operand(usize),
    Flag,
    Value(&'a str),
}

/// A word of a command line: as the person typed it, or a placeholder Immunity Core put in.
#[derive(Clone, Debug, PartialEq)]
enum Word {
    Typed(String),
    Placeholder(&'static str),
}

/// The flags that take a value, with the placeholder shown for it: the parser takes the word
/// after each as its value, whatever it is.
const VALUES: &[(&str, &str)] = &[
    ("--store", "<path>"),
    ("--reason", "<text>"),
    ("--days", "<n>"),
    ("--via", "app|agent"),
    ("--with", "<id>"),
    ("--journal-seq", "<n>"),
    ("--tailscale", "<path>"),
    ("--machine-name", "<name>"),
    ("--brew", "<path>"),
    ("--brew-input", "<file>"),
    ("--servers-input", "<dir>"),
    ("--checkouts-root", "<dir>"),
    ("--sessions-root", "<dir>"),
    ("--threats-input", "<file>"),
    ("--osv-crates-input", "<file>"),
    ("--osv-npm-input", "<file>"),
    ("--curl", "<path>"),
    ("--system-root", "<dir>"),
    ("--indicators", "<file>"),
    ("--sample-input", "<file>"),
    ("--sample-every", "<seconds>"),
    ("--events-every", "<seconds>"),
    ("--alive-every", "<seconds>"),
    ("--after", "<place>"),
    ("--limit", "<n>"),
    ("--launchctl", "<path>"),
    ("--home", "<dir>"),
];

fn placeholder(flag: &str) -> Option<&'static str> {
    VALUES.iter().find(|(f, _)| *f == flag).map(|(_, p)| *p)
}

/// The command line as typed, read as the parser reads it: which words are flags, which are
/// their values and which are operands.
struct Typed(Vec<Word>);

impl Typed {
    /// The positions of the operands: words that are neither a flag nor a flag's value.
    fn operands(&self) -> Vec<usize> {
        let mut out = Vec::new();
        let mut i = 0;
        while i < self.0.len() {
            match &self.0[i] {
                Word::Typed(w) if placeholder(w).is_some() => i += 2,
                Word::Typed(w) if w.starts_with("--") => i += 1,
                _ => {
                    out.push(i);
                    i += 1;
                }
            }
        }
        out
    }

    /// The position of the `n`th time `flag` is given as a flag, not as another flag's value.
    fn flag(&self, flag: &str, n: usize) -> Option<usize> {
        let mut i = 0;
        let mut seen = 0;
        while i < self.0.len() {
            if self.0[i] == Word::Typed(flag.to_string()) {
                if seen == n {
                    return Some(i);
                }
                seen += 1;
            }
            i += match &self.0[i] {
                Word::Typed(w) if placeholder(w).is_some() => 2,
                _ => 1,
            };
        }
        None
    }

    /// Takes out `flag` the `n`th time, with its value.
    fn remove(&mut self, flag: &str, n: usize) {
        if let Some(at) = self.flag(flag, n) {
            let end = if placeholder(flag).is_some() {
                (at + 2).min(self.0.len())
            } else {
                at + 1
            };
            self.0.drain(at..end);
        }
    }

    /// The value of `flag` set to its placeholder, or the flag and its placeholder added.
    fn value(&mut self, flag: &str) {
        self.value_of(flag, 0);
    }

    /// The value of `flag` the `n`th time set to its placeholder, or the flag and its
    /// placeholder added.
    fn value_of(&mut self, flag: &str, n: usize) {
        let shown = placeholder(flag).unwrap_or("<value>");
        match self.flag(flag, n) {
            Some(at) if at + 1 < self.0.len() => self.0[at + 1] = Word::Placeholder(shown),
            Some(_) => self.0.push(Word::Placeholder(shown)),
            None => {
                self.0.push(Word::Typed(flag.to_string()));
                self.0.push(Word::Placeholder(shown));
            }
        }
    }

    /// The operands after the first `keep` taken out.
    fn keep_operands(&mut self, keep: usize) {
        for at in self.operands().into_iter().skip(keep).rev() {
            self.0.remove(at);
        }
    }

    /// Placeholders put after the operands there are, until there is one for each of `shown`.
    fn operands_at_least(&mut self, shown: &[&'static str]) {
        let have = self.operands().len();
        for p in shown.iter().skip(have) {
            let at = self.operands().last().map_or(0, |i| i + 1);
            self.0.insert(at, Word::Placeholder(p));
        }
    }

    /// The words in one fixed order, whatever order they were typed in: the command's own words
    /// (its operands), then its flags as typed, then `--store` and last the form, each flag with
    /// its value.
    fn ordered(&self) -> Vec<(&Word, Role<'_>)> {
        let text = |w: &Word| match w {
            Word::Typed(t) => t.clone(),
            Word::Placeholder(p) => p.to_string(),
        };
        let mut operands: Vec<(&Word, Role)> = Vec::new();
        let mut flags: Vec<(u8, Vec<(&Word, Role)>)> = Vec::new();
        let mut i = 0;
        while i < self.0.len() {
            let word = text(&self.0[i]);
            if word.starts_with("--") {
                let mut group = vec![(&self.0[i], Role::Flag)];
                if let Word::Typed(flag) = &self.0[i]
                    && placeholder(flag).is_some()
                    && let Some(value) = self.0.get(i + 1)
                {
                    group.push((value, Role::Value(flag.as_str())));
                }
                i += group.len();
                let rank = match word.as_str() {
                    "--store" => 1,
                    w if w.starts_with("--json") || w.starts_with("--proto") => 2,
                    _ => 0,
                };
                flags.push((rank, group));
            } else {
                operands.push((&self.0[i], Role::Operand(operands.len())));
                i += 1;
            }
        }
        flags.sort_by_key(|(rank, _)| *rank);
        operands
            .into_iter()
            .chain(flags.into_iter().flat_map(|(_, f)| f))
            .collect()
    }

    /// The line, in the fixed order (`ordered`), each word typed as the shell reads it back
    /// (`text::shell_word`); a word that cannot be shown exactly is never echoed in it: its
    /// placeholder takes its place, and a sentence says what was left out.
    fn line(&self, op: &str) -> Pasted {
        let mut out = format!("immunity {op}");
        let mut left: Vec<String> = Vec::new();
        for (w, role) in self.ordered() {
            out.push(' ');
            match w {
                Word::Placeholder(p) => out.push_str(p),
                Word::Typed(t) => match crate::text::shell_word(t) {
                    Some(word) => out.push_str(&word),
                    None => {
                        let (shown, named) = match role {
                            Role::Value(flag) => (
                                placeholder(flag).unwrap_or("<value>"),
                                format!("the value of {flag}"),
                            ),
                            Role::Operand(n) => {
                                let p = operand_placeholder(op, n);
                                (p, p.to_string())
                            }
                            Role::Flag => ("<flag>", "a flag".to_string()),
                        };
                        out.push_str(shown);
                        left.push(named);
                    }
                },
            }
        }
        let left_out = match left.as_slice() {
            [] => None,
            [one] => Some(format!(
                "What was typed for {one} cannot be shown here exactly, so it was left out; \
                 type it in its place."
            )),
            [rest @ .., last] => Some(format!(
                "What was typed for {} and {last} cannot be shown here exactly, so it was left \
                 out; type each in its place.",
                rest.join(", ")
            )),
        };
        Pasted {
            command: out,
            left_out,
        }
    }
}

/// What a refusal of an answer to a finding gives a person to run next, made from the command
/// as typed as a misuse's right form is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FindingNext {
    /// The finding read again, before an answer: what changed has to be seen first.
    Read,
    /// The answer taken back.
    Reopen,
    /// The same command with the finding named by the `n`th `--with` left for the person to
    /// give.
    OtherId(usize),
    /// The list of every finding, to find the id in.
    List,
}

/// The command a refusal of `immunity finding <id> <answer>` gives a person to run next. `args`
/// are the words typed after `finding`; the id and `--store` are kept as typed, each word cut of
/// secrets and escaped (`Typed::line`).
pub fn finding_next(args: &[String], next: FindingNext) -> Pasted {
    let typed = Typed(args.iter().cloned().map(Word::Typed).collect());
    let mut kept: Vec<Word> = vec![
        typed
            .operands()
            .first()
            .map_or(Word::Placeholder("<id>"), |&at| typed.0[at].clone()),
    ];
    let verb = match next {
        FindingNext::List => return Pasted::own("immunity findings --all"),
        FindingNext::OtherId(n) => {
            let mut typed = typed;
            typed.value_of("--with", n);
            return typed.line("finding");
        }
        FindingNext::Reopen => {
            kept.push(Word::Typed("reopen".to_string()));
            Some("reopen")
        }
        FindingNext::Read => None,
    };
    // Every flag typed that the command given next takes, with its value, as typed.
    // `--with` may be given more than once, and each is kept.
    for flag in form_flags("finding", verb) {
        for at in (0..).map_while(|n| typed.flag(flag, n)) {
            let takes = if placeholder(flag).is_some() { 2 } else { 1 };
            kept.extend(typed.0.iter().skip(at).take(takes).cloned());
        }
    }
    Typed(kept).line("finding")
}

/// Where the parser's words stop being the cause and start telling the right form, which the
/// error shows on a line of its own.
const HINTS: &[&str] = &[
    ": --",
    ", as in:",
    ", the journal_seq",
    ": <name>",
    "; for a place",
    ": the job runs",
    "; immunity vulnerability <id> does",
];

/// The cause of a misuse in Immunity Core's words and the command as typed in its right form: the one
/// thing wrong mended, every other word kept. Where the parser's words name no mending this
/// knows, the command's own form.
fn right_form(op: &str, args: &[String], said: &str) -> (String, Pasted) {
    let mut typed = Typed(args.iter().cloned().map(Word::Typed).collect());
    let quoted = |s: &str| crate::text::quoted(&crate::secrets::said(s));
    // What the parser said may repeat what was typed: cut and escaped as any such text.
    let mut cause = crate::secrets::said(
        HINTS
            .iter()
            .filter_map(|h| said.find(h))
            .min()
            .map_or(said, |at| &said[..at]),
    );
    // The form of the verb typed, such as `seen` or `retired`, else the command's first.
    let fallback = || {
        let Some(c) = COMMANDS.iter().find(|c| c.name == op) else {
            return format!("immunity {op}");
        };
        let names_verb = |f: &&&[&str]| {
            f[0].split([' ', '|'])
                .skip(2)
                .any(|w| args.iter().any(|a| a == w))
        };
        c.forms
            .iter()
            .skip(1)
            .find(names_verb)
            .unwrap_or(&c.forms[0])
            .join(" ")
    };
    let verb_at = |typed: &Typed| typed.operands().get(1).copied();
    if let Some(arg) = said.strip_prefix("unexpected argument: ") {
        cause = format!("immunity {op} does not take {}", quoted(arg));
        if let Some(at) = typed
            .0
            .iter()
            .position(|w| *w == Word::Typed(arg.to_string()))
        {
            typed.0.remove(at);
        }
    } else if let Some(flag) = said.strip_suffix(" needs a value that is not empty") {
        typed.value(flag);
    } else if let Some(flag) = said.strip_suffix(" needs a value") {
        typed.value(flag);
    } else if let Some(flag) = said.strip_suffix(" is given once") {
        typed.remove(flag, 1);
    } else if said.starts_with("--json and --proto") {
        cause = "--json and --proto each name the form of the answer; give one".to_string();
        let later = ["--json", "--proto"]
            .into_iter()
            .filter_map(|f| typed.flag(f, 0).map(|at| (at, f)))
            .max();
        if let Some((_, f)) = later {
            typed.remove(f, 0);
        }
    } else if said == "--machine-name needs a name" {
        typed.value("--machine-name");
    } else if said.ends_with(": --reason <text>") {
        typed.value("--reason");
    } else if said.contains(" needs --journal-seq <n>") {
        typed.value("--journal-seq");
    } else if let Some(flag) = [
        "--journal-seq",
        "--days",
        "--limit",
        "--via",
        "--sample-every",
        "--events-every",
        "--alive-every",
    ]
    .into_iter()
    .find(|f| said.starts_with(&format!("{f} takes")))
    {
        typed.value(flag);
    } else if said == "seen takes no days" {
        typed.remove("--days", 0);
    } else if said == "reopen takes no reason and no days" {
        typed.remove("--reason", 0);
        typed.remove("--days", 0);
    } else if said == "a withdrawal takes no reason" {
        typed.remove("--reason", 0);
    } else if let Some(word) =
        said.strip_prefix("the owner can answer expected or seen, or reopen, not ")
    {
        cause = format!(
            "{} is not an answer: expected, seen or reopen",
            quoted(word)
        );
        if let Some(at) = verb_at(&typed) {
            typed.0[at] = Word::Placeholder("expected|seen|reopen");
        }
    } else if let Some(word) =
        said.strip_prefix("the owner can say retired or not-mine, or withdraw, not ")
    {
        cause = format!(
            "{} is not a statement: retired, not-mine or withdraw",
            quoted(word)
        );
        if let Some(at) = verb_at(&typed) {
            typed.0[at] = Word::Placeholder("retired|not-mine|withdraw");
        }
    } else if said
        .starts_with("--reason, --days, --via, --with and --journal-seq go with an answer")
    {
        typed.operands_at_least(&["<id>"]);
        let at = typed.operands()[0] + 1;
        typed
            .0
            .insert(at, Word::Placeholder("expected|seen|reopen"));
    } else if said.starts_with("--reason and --via go with a statement") {
        typed.0.insert(0, Word::Placeholder("retired|not-mine"));
        typed.0.insert(0, Word::Placeholder("<name>"));
    } else if said.starts_with("immunity finding takes an id") {
        typed.keep_operands(2);
        typed.operands_at_least(&["<id>"]);
    } else if said.starts_with("immunity owner takes a name and what the owner says") {
        typed.keep_operands(2);
        typed.operands_at_least(&["<name>", "retired|not-mine|withdraw"]);
    } else if said.starts_with("immunity vulnerability takes one record id") {
        typed.keep_operands(1);
        typed.operands_at_least(&["<id>"]);
    } else if said.starts_with("immunity vulnerabilities takes no id") {
        typed.keep_operands(0);
    } else if said.starts_with("immunity project takes")
        || said.starts_with("immunity program takes")
        || said.starts_with("immunity machine takes")
    {
        let shown = match op {
            "project" => "<path or id>",
            "program" => "<path, name or id>",
            _ => "<name or id>",
        };
        let keep = typed.operands().len().min(1);
        typed.keep_operands(keep);
        if let Some(at) = typed.operands().first().copied() {
            typed.0[at] = Word::Placeholder(shown);
        } else if op != "machine" {
            typed.0.insert(0, Word::Placeholder(shown));
        }
    } else if said.starts_with("--after takes") {
        typed.remove("--after", 0);
    } else if said == "--system-root is for immunity rules --over-log" {
        typed.0.insert(0, Word::Typed("--over-log".to_string()));
    } else if said.ends_with("takes no --store: the job runs with the store in its usual place") {
        typed.remove("--store", 0);
    } else if said == "--home and --launchctl are for tests and go only together" {
        typed.value(if typed.flag("--home", 0).is_some() {
            "--launchctl"
        } else {
            "--home"
        });
    } else if said.starts_with("immunity verdict reads one message") {
        cause = "immunity verdict needs a form, --json or --proto".to_string();
        typed.0.push(Word::Placeholder("--json|--proto"));
    } else {
        return (crate::secrets::said(said), Pasted::own(&fallback()));
    }
    (cause, typed.line(op))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(args: &[&str]) -> Vec<String> {
        args.iter().map(|a| a.to_string()).collect()
    }

    #[test]
    fn a_misuse_shows_the_typed_command_mended_with_the_person_s_own_values() {
        let cases: &[(&str, &[&str], &str, &str)] = &[
            (
                "finding",
                &["f0123456789", "expected"],
                "expected needs a reason: --reason <text>",
                "immunity finding f0123456789 expected --reason <text>",
            ),
            (
                "finding",
                &["f0123456789", "dismiss"],
                "the owner can answer expected or seen, or reopen, not dismiss",
                "immunity finding f0123456789 expected|seen|reopen",
            ),
            (
                "findings",
                &["--frob", "--all"],
                "unexpected argument: --frob",
                "immunity findings --all",
            ),
            (
                "owner",
                &["box", "retired", "--reason", ""],
                "a statement needs a reason: --reason <text>",
                "immunity owner box retired --reason <text>",
            ),
            (
                "finding",
                &["f0123456789", "seen", "--via", "agent", "--reason", "ok"],
                "an answer through an agent needs --journal-seq <n>, the journal_seq of the answer",
                "immunity finding f0123456789 seen --via agent --reason ok --journal-seq <n>",
            ),
            (
                "finding",
                &["f0123456789", "seen", "--days", "3"],
                "seen takes no days",
                "immunity finding f0123456789 seen",
            ),
            (
                "matches",
                &["--limit", "0"],
                "--limit takes a whole number of at least 1",
                "immunity matches --limit <n>",
            ),
            (
                "status",
                &["--store"],
                "--store needs a value",
                "immunity status --store <path>",
            ),
            (
                "finding",
                &[
                    "f0123456789",
                    "seen",
                    "--journal-seq",
                    "1",
                    "--journal-seq",
                    "2",
                ],
                "--journal-seq is given once",
                "immunity finding f0123456789 seen --journal-seq 1",
            ),
            (
                "rules",
                &["--system-root", "/x"],
                "--system-root is for immunity rules --over-log",
                "immunity rules --over-log --system-root /x",
            ),
            (
                "finding",
                &[],
                "immunity finding takes an id, as in: immunity finding f0123456789 seen",
                "immunity finding <id>",
            ),
            (
                "finding",
                &["f0123456789", "--reason", "my reason"],
                "--reason, --days, --via, --with and --journal-seq go with an answer: expected, seen or reopen",
                "immunity finding f0123456789 expected|seen|reopen --reason 'my reason'",
            ),
        ];
        for (op, args, said, form) in cases {
            let (_, shown) = right_form(op, &words(args), said);
            assert_eq!(&shown.command, form, "{op} {args:?}");
        }
    }

    #[test]
    fn every_misuse_the_parser_names_is_mended_in_its_own_way() {
        let cases: &[(&str, &[&str], &str, &str)] = &[
            (
                "finding",
                &["f0", "seen", "--with", ""],
                "--with needs a value that is not empty",
                "immunity finding f0 seen --with <id>",
            ),
            (
                "status",
                &["--json", "--proto"],
                "--json and --proto each name the form of the answer; give one",
                "immunity status --json",
            ),
            (
                "run",
                &["--machine-name", ""],
                "--machine-name needs a name",
                "immunity run --machine-name <name>",
            ),
            // Whatever order they were typed in, the command's own words come first, then its
            // flags, then the store, then the form.
            (
                "finding",
                &["--json", "--store", "/s", "f0", "--with", "", "seen"],
                "--with needs a value that is not empty",
                "immunity finding f0 seen --with <id> --store /s --json",
            ),
            (
                "finding",
                &["f0", "seen", "--journal-seq", "x"],
                "--journal-seq takes the journal_seq an answer gave, a number",
                "immunity finding f0 seen --journal-seq <n>",
            ),
            (
                "finding",
                &["f0", "expected", "--reason", "r", "--days", "0"],
                "--days takes a number of days from 1 to 3650",
                "immunity finding f0 expected --reason r --days <n>",
            ),
            (
                "watch",
                &["--sample-every", "0"],
                "--sample-every takes a number of seconds from 1 to 3600",
                "immunity watch --sample-every <seconds>",
            ),
            (
                "finding",
                &["f0", "seen", "--via", "x"],
                "--via takes app or agent",
                "immunity finding f0 seen --via app|agent",
            ),
            (
                "finding",
                &["f0", "reopen", "--reason", "r", "--days", "2"],
                "reopen takes no reason and no days",
                "immunity finding f0 reopen",
            ),
            (
                "owner",
                &["box", "withdraw", "--reason", "r"],
                "a withdrawal takes no reason",
                "immunity owner box withdraw",
            ),
            (
                "owner",
                &["box", "gone"],
                "the owner can say retired or not-mine, or withdraw, not gone",
                "immunity owner box retired|not-mine|withdraw",
            ),
            (
                "owner",
                &["--reason", "r"],
                "--reason and --via go with a statement: <name> retired, not-mine or withdraw",
                "immunity owner <name> retired|not-mine --reason r",
            ),
            (
                "owner",
                &["box"],
                "immunity owner takes a name and what the owner says",
                "immunity owner box retired|not-mine|withdraw",
            ),
            // A flag's value is never taken for an operand.
            (
                "owner",
                &["--reason", "r", "box"],
                "immunity owner takes a name and what the owner says",
                "immunity owner box retired|not-mine|withdraw --reason r",
            ),
            (
                "vulnerability",
                &["a", "b", "c"],
                "immunity vulnerability takes one record id or CVE id, as in: immunity vulnerability CVE-2023-4863",
                "immunity vulnerability a",
            ),
            (
                "vulnerability",
                &["a", "b"],
                "immunity vulnerability takes one record id or CVE id, as in: immunity vulnerability CVE-2023-4863",
                "immunity vulnerability a",
            ),
            (
                "vulnerabilities",
                &["a"],
                "immunity vulnerabilities takes no id; immunity vulnerability <id> does",
                "immunity vulnerabilities",
            ),
            (
                "project",
                &["dev/shop"],
                "immunity project takes a path on this Mac",
                "immunity project <path or id>",
            ),
            (
                "program",
                &[],
                "immunity program takes a path on this Mac",
                "immunity program <path, name or id>",
            ),
            (
                "machine",
                &["a", "b"],
                "immunity machine takes nothing for this Mac, or one machine",
                "immunity machine <name or id>",
            ),
            (
                "matches",
                &["--after", "zz", "--limit", "2"],
                "--after takes the place an answer of immunity matches printed; for a place this version cannot read",
                "immunity matches --limit 2",
            ),
            (
                "on",
                &["--store", "x"],
                "immunity on takes no --store: the job runs with the store in its usual place",
                "immunity on",
            ),
            (
                "on",
                &["--home", "/h"],
                "--home and --launchctl are for tests and go only together",
                "immunity on --home /h --launchctl <path>",
            ),
            (
                "verdict",
                &[],
                "immunity verdict reads one message and answers in the same form, which is never text: name it, --proto or --json",
                "immunity verdict --json|--proto",
            ),
        ];
        for (op, args, said, form) in cases {
            let (cause, shown) = right_form(op, &words(args), said);
            assert_eq!(&shown.command, form, "{op} {args:?}");
            assert!(
                !cause.contains(": --") && !cause.contains("as in:"),
                "{cause}"
            );
        }
    }

    #[test]
    fn the_cause_of_a_misuse_stops_where_its_right_form_begins() {
        let (cause, _) = right_form(
            "finding",
            &words(&["f0123456789", "expected"]),
            "expected needs a reason: --reason <text>",
        );
        assert_eq!(cause, "expected needs a reason");
        let (cause, _) = right_form(
            "findings",
            &words(&["x\u{1b}[31m"]),
            "unexpected argument: x\u{1b}[31m",
        );
        assert_eq!(cause, r#"immunity findings does not take "x\u{1b}[31m""#);
    }

    #[test]
    fn a_misuse_this_does_not_know_shows_the_command_s_own_form() {
        let (cause, form) = right_form("finding", &words(&["f0", "seen"]), "something new");
        assert_eq!(cause, "something new");
        assert!(
            form.command.starts_with("immunity finding <id> seen"),
            "{form:?}"
        );
    }

    #[test]
    fn the_help_names_every_command_the_parser_takes_and_the_parser_takes_no_other() {
        let help = help(&Screen::pipe());
        for c in COMMANDS {
            // A command the parser knows fails, if at all, on its arguments, never as unknown.
            let parsed = crate::parse_args(
                Some(c.name),
                ["--machine-name", "m", "--store", "/nonexistent/store.db"]
                    .iter()
                    .map(|s| s.to_string()),
                &mut crate::answer::Options::default(),
                &mut false,
            );
            if let Err(e) = parsed {
                assert!(!e.starts_with("unknown command"), "{}: {e}", c.name);
            }
            assert!(
                help.contains(&format!("  immunity {}", c.name)),
                "{} is not in the help",
                c.name
            );
            assert!(command_help(c.name, &Screen::pipe()).is_some());
        }
        let parsed = crate::parse_args(
            Some("frobnicate"),
            std::iter::empty(),
            &mut crate::answer::Options::default(),
            &mut false,
        );
        assert!(matches!(parsed, Err(e) if e == "unknown command: frobnicate"));
    }

    /// `immunity on` and `immunity off` took the place of the earlier words, with no alias: those
    /// get what any word that is not a command gets. Below the command line, so a test never
    /// runs the real thing the day this broke.
    #[test]
    fn the_old_words_install_and_uninstall_are_not_commands() {
        for word in ["install", "uninstall"] {
            let parsed = crate::parse_args(
                Some(word),
                std::iter::empty(),
                &mut crate::answer::Options::default(),
                &mut false,
            );
            assert!(matches!(parsed, Err(e) if e == format!("unknown command: {word}")));
            assert!(command_help(word, &Screen::pipe()).is_none());
        }
    }

    #[test]
    fn a_refused_answer_gives_the_command_to_run_next_made_from_the_one_typed_with_every_flag_it_takes()
     {
        let typed = words(&[
            "f0123456789",
            "seen",
            "--with",
            "f7a76b7b86f",
            "--journal-seq",
            "4",
            "--via",
            "agent",
            "--store",
            "/x/s.db",
        ]);
        for (next, said) in [
            (
                FindingNext::Read,
                "immunity finding f0123456789 --store /x/s.db",
            ),
            // Reopen takes --via, --with and --journal-seq: an agent's answer stays one.
            (
                FindingNext::Reopen,
                "immunity finding f0123456789 reopen --via agent --with f7a76b7b86f --journal-seq 4 --store /x/s.db",
            ),
            (
                FindingNext::OtherId(0),
                "immunity finding f0123456789 seen --with <id> --journal-seq 4 --via agent --store /x/s.db",
            ),
            (FindingNext::List, "immunity findings --all"),
        ] {
            assert_eq!(finding_next(&typed, next).command, said, "{next:?}");
        }
        // Of several --with, the one refused is left to name, and reopen keeps every one.
        let typed = words(&["f0", "seen", "--with", "f1", "--with", "f2"]);
        assert_eq!(
            finding_next(&typed, FindingNext::OtherId(1)).command,
            "immunity finding f0 seen --with f1 --with <id>"
        );
        assert_eq!(
            finding_next(&typed, FindingNext::Reopen).command,
            "immunity finding f0 reopen --with f1 --with f2"
        );
        // Without an id typed, the place for one; without a store, none.
        assert_eq!(
            finding_next(&words(&["--reason", "r"]), FindingNext::Reopen).command,
            "immunity finding <id> reopen"
        );
    }

    /// The words of a command line as a POSIX shell splits them: single quotes, double quotes
    /// and backslashes, the three ways a word printed here may be written.
    fn shell_split(line: &str) -> Vec<String> {
        let mut out = Vec::new();
        let mut word: Option<String> = None;
        let mut chars = line.chars();
        while let Some(c) = chars.next() {
            match c {
                ' ' => out.extend(word.take()),
                '\'' => {
                    let w = word.get_or_insert_with(String::new);
                    for q in chars.by_ref() {
                        if q == '\'' {
                            break;
                        }
                        w.push(q);
                    }
                }
                '\\' => {
                    let w = word.get_or_insert_with(String::new);
                    w.extend(chars.next());
                }
                c => word.get_or_insert_with(String::new).push(c),
            }
        }
        out.extend(word);
        out
    }

    #[test]
    fn a_printed_command_names_exactly_what_was_typed_or_the_placeholder_and_says_so() {
        let hostile = [
            "store/a;touch${IFS}x",
            "$(touch x)",
            "`touch x`",
            "~/s.db",
            "#s",
            "a&b",
            "*.db",
            "it's",
            "my store",
            "\"q\"",
            "",
            "a\\b",
            "a\nb",
            "a\u{1b}[31mb",
            "a\u{202e}b",
            "plain/path-1.db",
        ];
        for value in hostile {
            let typed = words(&["f0", "seen", "--with", "", "--store", value]);
            let (_, form) = right_form("finding", &typed, "--with needs a value that is not empty");
            // As the screen shows it (`Step::Command`), and as the shell would read it back.
            let split = shell_split(&crate::view::shown(&form.command));
            let at = split.iter().position(|w| w == "--store").unwrap();
            let shown = &split[at + 1];
            if shown == "<path>" {
                // Left out: never echoed, and said so under the command.
                assert!(
                    value.contains(['\\', '\n', '\u{1b}', '\u{202e}']),
                    "{value:?} left out: {form:?}"
                );
                assert!(
                    form.left_out
                        .as_deref()
                        .is_some_and(|l| l.contains("--store") && l.contains("left out")),
                    "{form:?}"
                );
            } else {
                assert_eq!(shown, value, "{form:?}");
                assert_eq!(form.left_out, None, "{form:?}");
                // Read back, the whole command is what was typed, in the fixed order.
                assert_eq!(
                    split,
                    [
                        "immunity", "finding", "f0", "seen", "--with", "<id>", "--store", value
                    ],
                    "{form:?}"
                );
            }
        }
        // A word of the safe set is printed as it is; `~` is not of it.
        assert_eq!(
            crate::text::shell_word("plain/path-1.db").as_deref(),
            Some("plain/path-1.db")
        );
        assert_eq!(
            crate::text::shell_word("~/s.db").as_deref(),
            Some("'~/s.db'")
        );
        assert_eq!(crate::text::shell_word("=ls").as_deref(), Some("'=ls'"));
        // An operand that cannot be shown takes the operand's placeholder.
        let (_, form) = right_form(
            "finding",
            &words(&["f0\u{7}", "seen", "--with", ""]),
            "--with needs a value that is not empty",
        );
        assert_eq!(form.command, "immunity finding <id> seen --with <id>");
        assert!(form.left_out.is_some_and(|l| l.contains("<id>")));
    }

    #[test]
    fn every_flag_a_command_s_help_lists_is_one_the_parser_takes_for_that_command() {
        for c in COMMANDS {
            let flags: Vec<&str> = c
                .forms
                .iter()
                .flat_map(|f| f.iter())
                .flat_map(|w| w.split(|ch: char| ch.is_whitespace() || "[]|()".contains(ch)))
                .filter(|w| w.starts_with("--"))
                .collect();
            for flag in flags {
                let mut args = vec![flag.to_string()];
                if placeholder(flag).is_some() {
                    args.push("1".to_string());
                }
                let parsed = crate::parse_args(
                    Some(c.name),
                    args.into_iter(),
                    &mut crate::answer::Options::default(),
                    &mut false,
                );
                if let Err(e) = parsed {
                    assert!(
                        e != format!("unexpected argument: {flag}"),
                        "immunity {} {flag}: {e}",
                        c.name
                    );
                }
            }
        }
    }

    #[test]
    fn the_help_leaves_the_flags_for_tests_to_the_reference() {
        let help = help(&Screen::pipe());
        for flag in [
            "--brew",
            "--servers-input",
            "--osv-crates-input",
            "--curl",
            "--system-root",
            "--launchctl",
            "--home",
            "--machine-name",
            "--threats-input",
            "--checkouts-root",
            "--sessions-root",
            "--indicators",
            "--sample-input",
            "--tailscale",
        ] {
            assert!(!help.contains(flag), "{flag}");
        }
        assert!(help.contains("docs/reference.md"));
        assert!(!help.contains("hide"));
    }

    #[test]
    fn the_help_on_a_terminal_marks_commands_and_labels_and_in_a_pipe_nothing() {
        let painted = help(&Screen::terminal(80, true));
        assert!(painted.contains("\u{1b}[36mimmunity on\u{1b}[0m"));
        assert!(painted.contains("\u{1b}[1mAnswer a finding\u{1b}[0m"));
        assert!(!help(&Screen::pipe()).contains('\u{1b}'));
    }

    #[test]
    fn the_help_and_each_command_s_help_fit_eighty_columns() {
        let screen = Screen::pipe();
        let mut all = help(&screen);
        for c in COMMANDS {
            all.push_str(&command_help(c.name, &screen).unwrap());
        }
        for line in all.lines() {
            assert!(columns(line) <= 80, "{} columns: {line}", columns(line));
        }
    }

    #[test]
    fn the_help_of_finding_tells_an_agent_when_it_may_answer_in_the_words_every_listing_gives() {
        let help = command_help("finding", &Screen::pipe()).unwrap();
        let help = help.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(help.contains(crate::findings::ANSWERS_NOTE), "{help}");
    }
}
