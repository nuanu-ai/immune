//! Promises of `immunity program` and `immunity machine`, the questions of the contract beside
//! `immunity project`: what the store knows of one program installed on this Mac, and of one
//! machine, each as the same `Known` message. Each test runs the real binary over an invented
//! home folder, an invented system root and invented server files, so no test reads anything of
//! the Mac it runs on or asks the network.

mod common;

use immunity_contract::v1;
use prost::Message;
use serde_json::Value;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

/// An invented estate: a home folder, a system root, Homebrew's answer and the sweep's files.
struct Estate(PathBuf);

impl Estate {
    fn new(tag: &str) -> Estate {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "immunity-questions-{tag}-{}-{nanos}",
            std::process::id()
        ));
        for dir in ["home", "system", "servers"] {
            std::fs::create_dir_all(path.join(dir)).unwrap();
        }
        // Made real, as the readers make the home folder real: the temporary folder is a link.
        let e = Estate(std::fs::canonicalize(path).unwrap());
        e.put("brew.json", r#"{"formulae": [], "casks": []}"#);
        e
    }

    fn home(&self) -> PathBuf {
        self.0.join("home")
    }

    fn store(&self) -> PathBuf {
        self.0.join("store.db")
    }

    /// Writes a file under the estate, making the folders on the way.
    fn put(&self, rel: &str, content: &str) {
        let path = self.0.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, content).unwrap();
    }

    /// An application bundle under the system root's `/Applications`.
    fn app(&self, folder: &str, identifier: &str, version: &str) {
        self.app_in("system/Applications", folder, identifier, version);
    }

    /// An application bundle in a folder of the estate.
    fn app_in(&self, dir: &str, folder: &str, identifier: &str, version: &str) {
        self.put(
            &format!("{dir}/{folder}/Contents/Info.plist"),
            &format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<plist version=\"1.0\"><dict>\
                 <key>CFBundleIdentifier</key><string>{identifier}</string>\
                 <key>CFBundleShortVersionString</key><string>{version}</string>\
                 </dict></plist>\n"
            ),
        );
        let stem = folder.trim_end_matches(".app");
        self.put(
            &format!("{dir}/{folder}/Contents/MacOS/{stem}"),
            "invented\n",
        );
    }

    /// A Homebrew keg and the formula Homebrew names for it.
    fn formula(&self, name: &str, version: &str) {
        self.put(
            &format!("system/opt/homebrew/Cellar/{name}/{version}/bin/{name}"),
            "invented\n",
        );
        self.put(
            "brew.json",
            &format!(
                r#"{{"formulae": [{{"full_name": "{name}", "tap": "homebrew/core", "installed": [{{"version": "{version}"}}]}}], "casks": []}}"#
            ),
        );
    }

    /// A global npm package, where Homebrew's node puts it.
    fn package(&self, name: &str, version: &str) {
        let dir = format!("system/opt/homebrew/lib/node_modules/{name}");
        self.put(
            &format!("{dir}/package.json"),
            &format!(r#"{{"name": "{name}", "version": "{version}"}}"#),
        );
        self.put(&format!("{dir}/index.js"), "module.exports = 1;\n");
    }

    /// A checkout as git leaves it, in the home folder.
    fn checkout(&self, rel: &str) {
        let git = format!("home/{rel}/.git");
        self.put(&format!("{git}/HEAD"), "ref: refs/heads/main\n");
        self.put(
            &format!("{git}/refs/heads/main"),
            "0123456789abcdef0123456789abcdef01234567\n",
        );
    }

    /// The binary with this home folder as the home and the estate as the working folder.
    fn immunity(&self) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_immunity"));
        cmd.env("HOME", self.home()).current_dir(&self.0);
        cmd
    }

    /// `immunity run` for the machine `mac` on this estate alone.
    fn run(&self) {
        let at = |name: &str| self.0.join(name);
        let out = self
            .immunity()
            .args(["run", "--machine-name", "mac", "--store"])
            .arg(self.store())
            .arg("--system-root")
            .arg(at("system"))
            .arg("--brew-input")
            .arg(at("brew.json"))
            .arg("--servers-input")
            .arg(at("servers"))
            .arg("--tailscale")
            .arg(at("no-tailscale"))
            .arg("--threats-input")
            .arg(at("no-catalogue"))
            .arg("--osv-crates-input")
            .arg(at("osv-crates.zip"))
            .arg("--osv-npm-input")
            .arg(at("osv-npm.zip"))
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    /// `immunity <question> [<what>]` on this store, with these arguments after.
    fn ask(&self, question: &str, what: Option<&str>, extra: &[&str]) -> Output {
        self.immunity()
            .arg(question)
            .args(what)
            .arg("--store")
            .arg(self.store())
            .args(extra)
            .output()
            .unwrap()
    }

    /// The answer in binary, decoded with the generated types.
    fn known(&self, question: &str, what: Option<&str>) -> v1::Known {
        let out = self.ask(question, what, &["--proto"]);
        assert!(
            out.status.success(),
            "{what:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        v1::Known::decode(out.stdout.as_slice()).unwrap()
    }

    fn program(&self, what: &str) -> v1::Known {
        self.known("program", Some(what))
    }

    fn machine(&self, what: Option<&str>) -> v1::Known {
        self.known("machine", what)
    }

    /// The answer as JSON.
    fn json(&self, question: &str, what: Option<&str>) -> Value {
        let out = self.ask(question, what, &["--json"]);
        serde_json::from_slice(&out.stdout).unwrap()
    }
}

impl Drop for Estate {
    fn drop(&mut self) {
        common::remove(&self.0);
    }
}

/// The id of the thing an answer is about.
fn thing(k: &v1::Known) -> &str {
    &k.thing.as_ref().unwrap().id_text
}

/// Each reading in the answer as reader, kind, scope and completeness.
fn readings(k: &v1::Known) -> Vec<(&str, &str, &str, v1::Completeness)> {
    let mut out: Vec<_> = k
        .coverage
        .iter()
        .map(|c| {
            (
                c.reader.as_str(),
                c.kind.as_str(),
                c.scope_text.as_str(),
                c.completeness(),
            )
        })
        .collect();
    out.sort();
    out
}

fn all_full(k: &v1::Known) -> bool {
    k.coverage
        .iter()
        .all(|c| c.completeness() == v1::Completeness::Full)
}

fn has_fact(k: &v1::Known, subject: &str, predicate: &str) -> bool {
    k.facts
        .iter()
        .any(|f| f.subject_text == subject && f.predicate == predicate)
}

const BUNDLES: &str = "application bundles in /Applications and ~/Applications";
const KEGS: &str = "Homebrew kegs";
const NPM: &str = "global npm packages";
const BREW: &str = "brew packages";
const MANAGERS: &str = "software of package managers this version does not read";
const TINY: &str = "component:machine:mac/macos-app/org.example.tiny";
const KEG: &str = "file:machine:mac//opt/homebrew/Cellar/tool/1.0";

/// A server's sweep file as the probe writes it, with these package managers and dpkg rows.
fn server(managers: &str, dpkg: &str) -> String {
    format!(
        "##os\nInvented Linux\n##os_release\nID\tubuntu\nVERSION_ID\t24.04\nVERSION_CODENAME\tnoble\n\
         ##kernel\n6.8.0-45-generic\n##kernel_package\nlinux-image-6.8.0-45-generic\n\
         ##package_managers\n{managers}##reboot_required\nno\n##pve\n##dpkg_with_source\n{dpkg}\
         ##snap\n##docker_access\ndocker not installed\n##end\n"
    )
}

const BASH: &str = "ii \tbash\t5.2.21-2ubuntu4\tbash\t5.2.21-2ubuntu4\n";

/// The promise against false calm, for a program: one the store never heard of, one read in
/// full, and one known whose reading could not read all of it are three different answers. The
/// unknown one carries every reading that finds programs, so "unknown because nothing looked"
/// shows; a known one carries the readings of its own kind, not those of other kinds.
#[test]
fn unknown_known_and_read_in_full_and_known_but_not_read_are_three_different_program_answers() {
    let e = Estate::new("program-three");
    e.app("Tiny.app", "org.example.tiny", "2.0");
    // A package whose manifest is a link into a folder macOS asks permission for: the reader
    // records the package and does not follow the link, so its version is not read.
    e.package("linked", "0.1.0");
    e.put(
        "home/Documents/linked/package.json",
        r#"{"version": "0.1.0"}"#,
    );
    let manifest =
        e.0.join("system/opt/homebrew/lib/node_modules/linked/package.json");
    std::fs::remove_file(&manifest).unwrap();
    std::os::unix::fs::symlink(e.home().join("Documents/linked/package.json"), &manifest).unwrap();
    e.run();

    let unknown = e.program("/Applications/Ghost.app");
    assert_eq!(unknown.presence(), v1::Presence::Unknown);
    assert_eq!(unknown.thing, None);
    assert!(unknown.facts.is_empty() && unknown.parts.is_empty());
    let finders: Vec<(&str, &str)> = readings(&unknown)
        .iter()
        .map(|(reader, kind, scope, _)| {
            assert_eq!(*scope, "machine:mac");
            (*reader, *kind)
        })
        .collect();
    assert_eq!(
        finders,
        [
            ("brew", BREW),
            ("immunity", PLACES),
            ("immunity", LIMIT),
            ("integrity", KEGS),
            ("integrity", BUNDLES),
            ("integrity", NPM),
            ("integrity", MANAGERS)
        ]
    );

    let quiet = e.program("/Applications/Tiny.app");
    assert_eq!(quiet.presence(), v1::Presence::Held);
    assert_eq!(thing(&quiet), TINY);
    assert!(all_full(&quiet));
    assert_eq!(
        readings(&quiet),
        [("integrity", BUNDLES, "machine:mac", v1::Completeness::Full)]
    );
    assert!(has_fact(&quiet, TINY, "has_version"));

    let not_read = e.program("linked");
    assert_eq!(not_read.presence(), v1::Presence::Held);
    assert_eq!(thing(&not_read), "component:machine:mac/npm/linked");
    assert!(!has_fact(
        &not_read,
        "component:machine:mac/npm/linked",
        "has_version"
    ));
    let npm = &not_read.coverage[0];
    assert_eq!(
        (npm.kind.as_str(), npm.completeness(), npm.cause()),
        (NPM, v1::Completeness::Partial, v1::Cause::NotGiven)
    );
    assert!(
        npm.reason_text
            .as_deref()
            .is_some_and(|r| r.contains("linked/package.json")),
        "{:?}",
        npm.reason_text
    );
}

/// A program is one thing however it is asked for: its bundle, a file inside the bundle, its
/// bundle identifier and its id give the same answer; a keg and a file inside it give the keg;
/// a global package's folder gives the package. A path strictly inside adds only the reading
/// made by rule that it is not judged on its own. No path is looked at on disk.
#[test]
fn a_bundle_a_file_inside_it_its_identifier_and_its_id_are_the_same_program() {
    let e = Estate::new("program-same");
    e.app("Tiny.app", "org.example.tiny", "2.0");
    e.formula("tool", "1.0");
    e.package("left-pad", "1.3.0");
    e.run();
    let by_bundle = e.program("/Applications/Tiny.app");
    assert_eq!(thing(&by_bundle), TINY);
    for what in [
        "/Applications/Tiny.app/Contents/MacOS/Tiny",
        "/Applications/Ghost/../Tiny.app/",
        // A file inside it, as the store names a program's file that a sample saw run.
        "file:machine:mac//Applications/Tiny.app/Contents/MacOS/Tiny",
        "org.example.tiny",
        TINY,
    ] {
        let same = e.program(what);
        assert_eq!(
            (&same.thing, &same.facts, &store_read(&same)),
            (&by_bundle.thing, &by_bundle.facts, &by_bundle.coverage),
            "{what}"
        );
        assert_eq!(not_judged(&same), what.contains("/Contents/"), "{what}");
    }
    // Nothing on disk is asked: the bundle can be gone and the store still answers for it.
    std::fs::remove_dir_all(e.0.join("system/Applications/Tiny.app")).unwrap();
    assert_eq!(
        e.program("/Applications/Tiny.app/Contents/Info.plist")
            .facts,
        by_bundle.facts
    );

    for what in [
        "/opt/homebrew/Cellar/tool/1.0",
        "/opt/homebrew/Cellar/tool/1.0/bin/tool",
        KEG,
    ] {
        let keg = e.program(what);
        assert_eq!(thing(&keg), KEG, "{what}");
        assert!(has_fact(&keg, KEG, "has_digest"));
    }
    // A path next to a keg is not in it.
    assert_eq!(
        e.program("/opt/homebrew/Cellar/tool/1.0-old").presence(),
        v1::Presence::Unknown
    );
    let package = e.program("/opt/homebrew/lib/node_modules/left-pad/index.js");
    assert_eq!(thing(&package), "component:machine:mac/npm/left-pad");
    // The formula is a program of its own, named by Homebrew's name for it.
    let formula = e.program("tool");
    assert_eq!(thing(&formula), "component:machine:mac/brew/tool");
    assert_eq!(readings(&formula)[0].1, BREW);
}

/// The promise against false calm, for a program the store knows under several ids that no fact
/// links: a finding about any of them is in the answer however the program is asked for. A
/// Homebrew formula and its keg are one program, and so are an application and the folder of
/// code it keeps outside its bundle; the answer names the others in `same_as`.
#[test]
fn a_finding_about_any_id_of_a_program_is_in_the_answer_however_the_program_is_named() {
    let e = Estate::new("program-kin");
    e.formula("tool", "1.0");
    e.app("Editor.app", "org.example.editor", "3.0");
    e.put(
        "home/Library/Application Support/Editor/main.js",
        "start();\n",
    );
    e.run();
    // Files change in place while the versions stay.
    let append = |rel: &str| {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(e.0.join(rel))
            .unwrap();
        f.write_all(b"steal();\n").unwrap();
    };
    append("system/opt/homebrew/Cellar/tool/1.0/bin/tool");
    append("home/Library/Application Support/Editor/main.js");
    e.run();
    let rules = |k: &v1::Known| -> Vec<String> {
        k.findings
            .iter()
            .map(|f| f.rule.clone().unwrap_or_default())
            .collect()
    };
    let others =
        |k: &v1::Known| -> Vec<String> { k.same_as.iter().map(|s| s.id_text.clone()).collect() };
    let formula = "component:machine:mac/brew/tool";
    for what in ["tool", formula, "/opt/homebrew/Cellar/tool/1.0", KEG] {
        let k = e.program(what);
        assert_eq!(rules(&k), ["integrity.package-files"], "{what}");
        let mut ids = others(&k);
        ids.push(thing(&k).to_string());
        ids.sort();
        assert_eq!(ids, [formula, KEG], "{what}");
    }
    let editor = "component:machine:mac/macos-app/org.example.editor";
    let folder = "file:machine:mac/Library/Application Support/Editor";
    for what in ["org.example.editor", "/Applications/Editor.app", editor] {
        let k = e.program(what);
        assert_eq!(thing(&k), editor, "{what}");
        assert_eq!(rules(&k), ["integrity.app-code-outside"], "{what}");
        assert_eq!(others(&k), [folder], "{what}");
    }
    // The application removed with its folder: the finding about its code stays in its answer.
    std::fs::remove_dir_all(e.0.join("system/Applications/Editor.app")).unwrap();
    std::fs::remove_dir_all(e.home().join("Library/Application Support/Editor")).unwrap();
    e.run();
    let gone = e.program("org.example.editor");
    assert_eq!(gone.presence(), v1::Presence::Gone);
    assert_eq!(rules(&gone), ["integrity.app-code-outside"]);
    // A keg whose formula Homebrew does not name is found by the formula's name.
    e.put(
        "system/opt/homebrew/Cellar/loose/2.0/bin/loose",
        "invented\n",
    );
    e.run();
    assert_eq!(
        thing(&e.program("loose")),
        "file:machine:mac//opt/homebrew/Cellar/loose/2.0"
    );
}

/// Every id an answer gives for a program, and every path inside what the store holds of it, asks
/// back the same program with the same findings and the same readings: none of them is a program
/// the store never heard of, and none is a place no reading looks at. A folder of code an
/// application keeps outside its bundle, its id and a file in it answer for that application.
#[test]
fn every_id_and_path_of_a_program_answers_for_that_program_with_its_findings() {
    let e = Estate::new("program-every-id");
    e.formula("tool", "1.0");
    e.app("Editor.app", "org.example.editor", "3.0");
    e.put(
        "home/Library/Application Support/Editor/main.js",
        "start();\n",
    );
    e.run();
    for rel in [
        "system/opt/homebrew/Cellar/tool/1.0/bin/tool",
        "home/Library/Application Support/Editor/main.js",
    ] {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(e.0.join(rel))
            .unwrap();
        f.write_all(b"steal();\n").unwrap();
    }
    e.run();
    // The program as one answer gives it: its ids, its findings and its readings.
    type Of = (Vec<String>, Vec<String>, Vec<String>);
    let of = |k: &v1::Known| -> Of {
        let mut ids: Vec<String> = k.same_as.iter().map(|s| s.id_text.clone()).collect();
        ids.push(thing(k).to_string());
        ids.sort();
        let mut findings: Vec<String> = k.findings.iter().map(|f| f.id.clone()).collect();
        findings.sort();
        let read = store_read(k)
            .iter()
            .map(|c| format!("{} {}", c.reader, c.kind))
            .collect();
        (ids, findings, read)
    };
    for (name, paths) in [
        (
            "tool",
            [
                "/opt/homebrew/Cellar/tool/1.0",
                "/opt/homebrew/Cellar/tool/1.0/bin/tool",
            ],
        ),
        (
            "org.example.editor",
            [
                "~/Library/Application Support/Editor",
                "~/Library/Application Support/Editor/main.js",
            ],
        ),
    ] {
        let first = of(&e.program(name));
        assert_eq!(first.0.len(), 2, "{name}: {first:?}");
        assert_eq!(first.1.len(), 1, "{name}");
        for what in first.0.iter().map(String::as_str).chain(paths) {
            let k = e.program(what);
            assert_eq!(k.presence(), v1::Presence::Held, "{what}");
            assert_eq!(of(&k), first, "{what}");
            let inside = what.ends_with("/bin/tool") || what.ends_with(".js");
            assert_eq!(not_judged(&k), inside, "{what}");
            assert!(unread(&k).is_none() || inside, "{what}");
        }
    }
}

/// The reading made by rule that no reading opened the place asked about.
fn not_opened(k: &v1::Known) -> bool {
    unread(k).is_some_and(|c| {
        c.completeness() == v1::Completeness::None
            && c.reason_text
                .as_deref()
                .is_some_and(|r| r.starts_with("no reading opened this place"))
    })
}

/// The reading made by rule that a path strictly inside a program is not judged on its own.
fn not_judged(k: &v1::Known) -> bool {
    unread(k).is_some_and(|c| {
        c.completeness() == v1::Completeness::None
            && c.reason_text.as_deref().is_some_and(|r| {
                r.contains("a single path inside a program is not judged on its own")
            })
    })
}

/// The kind of the reading made by rule for a place asked about that is not judged on its own.
const PLACES: &str = "places the readings that find programs look in";

/// The readings of an answer the store holds, without the one made by rule for the place asked.
fn store_read(k: &v1::Known) -> Vec<v1::Coverage> {
    k.coverage
        .iter()
        .filter(|c| !(c.reader == "immunity" && c.kind == PLACES))
        .cloned()
        .collect()
}

/// A place in `~/Library/Application Support` that no reader opened is never answered as read:
/// a folder no application matched, a file in it, a helper application kept there, the folder
/// the core is installed in, and `Application Support` itself are each `unknown` with a reading
/// that is not full and says why. A place inside a folder of code, a cache its reading passes
/// over, answers for the application and is said not to be judged on its own.
#[test]
fn a_folder_under_application_support_no_reader_opened_is_never_answered_as_read() {
    let e = Estate::new("program-not-opened");
    e.app("Editor.app", "org.example.editor", "3.0");
    e.put(
        "home/Library/Application Support/Editor/main.js",
        "start();\n",
    );
    e.put(
        "home/Library/Application Support/Editor/Cache/chunk.js",
        "cached();\n",
    );
    e.put(
        "home/Library/Application Support/Evil/payload.js",
        "steal();\n",
    );
    e.put(
        "home/Library/Application Support/Tools/Helper.app/Contents/MacOS/Helper",
        "invented\n",
    );
    e.put(
        "home/Library/Application Support/ai.nuanu.immunity.core/bin/immunity",
        "invented\n",
    );
    e.run();
    for what in [
        "~/Library/Application Support/Evil/payload.js",
        "~/Library/Application Support/Evil",
        "~/Library/Application Support/Tools/Helper.app",
        "~/Library/Application Support/ai.nuanu.immunity.core/bin/immunity",
        "file:machine:mac/Library/Application Support/Evil",
        // `..` in an id is resolved before the id is matched: this is not Editor's.
        "file:machine:mac/Library/Application Support/Editor/../Evil/payload.js",
    ] {
        let k = e.program(what);
        assert_eq!(k.presence(), v1::Presence::Unknown, "{what}");
        assert_eq!(k.thing, None, "{what}");
        assert!(not_opened(&k), "{what}: {:?}", k.coverage);
        assert!(!all_full(&k), "{what}");
    }
    // A folder that holds a folder of code without being one says how many it holds.
    let holder = e.program("~/Library/Application Support");
    assert_eq!(holder.presence(), v1::Presence::Unknown);
    assert!(
        unread(&holder).is_some_and(|c| c
            .reason_text
            .as_deref()
            .is_some_and(|r| r.contains("it holds 1 program"))),
        "{:?}",
        holder.coverage
    );
    assert!(!all_full(&holder));
    let cache = e.program("~/Library/Application Support/Editor/Cache/chunk.js");
    assert_eq!(
        thing(&cache),
        "component:machine:mac/macos-app/org.example.editor"
    );
    assert!(not_judged(&cache), "{:?}", cache.coverage);
    assert!(!all_full(&cache));
}

const EDITOR: &str = "component:machine:mac/macos-app/org.example.editor";
const EDITOR_FOLDER: &str = "file:machine:mac/Library/Application Support/Editor";
const CODE: &str =
    "code kept by applications not signed by Apple under ~/Library/Application Support";
/// Every way to ask for the application Editor: its id, its name, its folder of code by path and
/// by id, and a file inside that folder.
const EDITOR_ASKED: [&str; 5] = [
    EDITOR,
    "org.example.editor",
    "~/Library/Application Support/Editor",
    EDITOR_FOLDER,
    "~/Library/Application Support/Editor/main.js",
];

/// The reading of applications' code in an answer.
fn code_reading(k: &v1::Known) -> &v1::Coverage {
    k.coverage
        .iter()
        .find(|c| c.kind == CODE)
        .unwrap_or_else(|| panic!("{:?}", k.coverage))
}

/// Appends a line to a file of the estate.
fn append(e: &Estate, rel: &str, line: &str) {
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .open(e.0.join(rel))
        .unwrap();
    f.write_all(line.as_bytes()).unwrap();
}

/// The promise against false calm, for an application that went while the folder of code it kept
/// outside its bundle stayed: the application is never answered `gone` while that folder is on
/// disk, and a change to the code in it is never invisible. Its bundle is removed, or moved out of
/// the places bundles are looked for, in the same run as a file in the folder is changed; the
/// reading keeps opening the folder, raises the finding of code changed outside a bundle, and says
/// in its note that the folder is compared though no application read now matches it. Asked by
/// the application's id, its name, the folder's path or id, or a file inside, in binary, JSON and
/// text, the answer is the same.
#[test]
fn an_application_that_went_while_its_code_folder_stayed_is_held_and_a_change_there_is_found() {
    for how in ["removed", "moved"] {
        let e = Estate::new(&format!("program-folder-left-{how}"));
        e.app("Editor.app", "org.example.editor", "3.0");
        e.put(
            "home/Library/Application Support/Editor/main.js",
            "start();\n",
        );
        e.run();
        // Updated once: the folder keeps the version it is at now, not an earlier one.
        e.app("Editor.app", "org.example.editor", "3.1");
        e.run();
        let bundle = e.0.join("system/Applications/Editor.app");
        if how == "removed" {
            std::fs::remove_dir_all(&bundle).unwrap();
        } else {
            std::fs::create_dir_all(e.home().join("Elsewhere")).unwrap();
            std::fs::rename(&bundle, e.home().join("Elsewhere/Editor.app")).unwrap();
        }
        append(
            &e,
            "home/Library/Application Support/Editor/main.js",
            "steal();\n",
        );
        e.run();
        for what in EDITOR_ASKED {
            let k = e.program(what);
            assert_eq!(k.presence(), v1::Presence::Held, "{how} {what}");
            assert_eq!(thing(&k), EDITOR, "{how} {what}");
            assert!(has_fact(&k, EDITOR_FOLDER, "has_digest"), "{how} {what}");
            assert!(!has_fact(&k, EDITOR, "installed_at"), "{how} {what}");
            let rules: Vec<&str> = k
                .findings
                .iter()
                .map(|f| f.rule.as_deref().unwrap_or_default())
                .collect();
            assert_eq!(rules, ["integrity.app-code-outside"], "{how} {what}");
            let code = code_reading(&k);
            assert_eq!(code.completeness(), v1::Completeness::Full, "{how} {what}");
            assert!(
                code.reason_text
                    .as_deref()
                    .is_some_and(|r| r.starts_with("0 folders matched an application")),
                "{how} {what}: {:?}",
                code.reason_text
            );
            assert!(
                code.reason_text.as_deref().is_some_and(|r| r.contains(
                    "though no application read now matches them: Library/Application Support/Editor"
                )),
                "{how} {what}: {:?}",
                code.reason_text
            );
            let json = e.json("program", Some(what));
            assert_eq!(json["presence"], "held", "{how} {what}");
            assert_eq!(
                json["findings"][0]["rule"], "integrity.app-code-outside",
                "{how} {what}"
            );
            let text = e.ask("program", Some(what), &[]);
            let text = String::from_utf8(text.stdout).unwrap();
            assert!(
                text.contains("App code in your Library folder changed")
                    && !text.contains("Gone:")
                    && !text.contains("has not"),
                "{how} {what}: {text}"
            );
        }
    }
}

/// A folder of code that really went from the disk is retracted, and the application whose bundle
/// went too is `gone`, by every way of asking for it, as before: a folder is held while it is
/// there and no longer.
#[test]
fn an_application_whose_bundle_and_code_folder_both_went_is_gone() {
    let e = Estate::new("program-folder-gone");
    e.app("Editor.app", "org.example.editor", "3.0");
    e.put(
        "home/Library/Application Support/Editor/main.js",
        "start();\n",
    );
    e.run();
    std::fs::remove_dir_all(e.0.join("system/Applications/Editor.app")).unwrap();
    e.run();
    assert_eq!(e.program(EDITOR).presence(), v1::Presence::Held);
    std::fs::remove_dir_all(e.home().join("Library/Application Support/Editor")).unwrap();
    e.run();
    for what in EDITOR_ASKED {
        let k = e.program(what);
        assert_eq!(k.presence(), v1::Presence::Gone, "{what}");
        assert_eq!(thing(&k), EDITOR, "{what}");
        assert!(k.facts.is_empty(), "{what}");
        assert!(
            store_read(&k)
                .iter()
                .all(|c| c.completeness() == v1::Completeness::Full),
            "{what}"
        );
    }
}

/// A folder of code held from an earlier reading that is now a link is there and is not opened:
/// the reading is not full and says why, so the application is not answered `gone`. So is a link
/// to the folder that holds the store, which the reading otherwise leaves out.
#[test]
fn a_held_code_folder_replaced_by_a_link_is_not_taken_for_gone() {
    for to in ["elsewhere", "the store's folder"] {
        let e = Estate::new("program-folder-link");
        e.app("Editor.app", "org.example.editor", "3.0");
        e.put("home/Elsewhere/Editor/main.js", "start();\n");
        e.put(
            "home/Library/Application Support/Editor/main.js",
            "start();\n",
        );
        e.run();
        std::fs::remove_dir_all(e.0.join("system/Applications/Editor.app")).unwrap();
        std::fs::remove_dir_all(e.home().join("Library/Application Support/Editor")).unwrap();
        let target = if to == "elsewhere" {
            e.home().join("Elsewhere/Editor")
        } else {
            e.store().parent().unwrap().to_path_buf()
        };
        std::os::unix::fs::symlink(target, e.home().join("Library/Application Support/Editor"))
            .unwrap();
        e.run();
        let k = e.program("org.example.editor");
        assert_ne!(k.presence(), v1::Presence::Gone, "{to}");
        let code = code_reading(&k);
        assert_eq!(code.completeness(), v1::Completeness::Partial, "{to}");
        assert!(
            code.reason_text.as_deref().is_some_and(
                |r| r.contains("Editor (held from an earlier reading and no longer a folder")
            ),
            "{to}: {:?}",
            code.reason_text
        );
    }
}

/// The findings of an answer, by rule.
fn rules_of(k: &v1::Known) -> Vec<&str> {
    k.findings
        .iter()
        .map(|f| f.rule.as_deref().unwrap_or_default())
        .collect()
}

/// The promise against false calm, for a folder of code that missed a reading: it is opened
/// again once it is back, read as for the first time, and compared from then on, so its
/// application is never answered `gone` while it is on disk and a change to it after its return
/// raises the finding. A folder renamed aside for one run and back, and one removed with its
/// application and made again, are each held on their return and raise nothing then.
#[test]
fn a_code_folder_that_comes_back_is_held_and_a_change_after_its_return_is_found() {
    for how in ["renamed aside", "made again"] {
        let e = Estate::new("program-folder-back");
        e.app("Editor.app", "org.example.editor", "3.0");
        let main = "home/Library/Application Support/Editor/main.js";
        e.put(main, "start();\n");
        e.run();
        let folder = e.home().join("Library/Application Support/Editor");
        let aside = e.home().join("Library/Application Support/Editor-aside");
        std::fs::remove_dir_all(e.0.join("system/Applications/Editor.app")).unwrap();
        if how == "renamed aside" {
            e.run();
            assert_eq!(e.program(EDITOR).presence(), v1::Presence::Held);
            std::fs::rename(&folder, &aside).unwrap();
            e.run();
            assert_eq!(e.program(EDITOR).presence(), v1::Presence::Gone);
            std::fs::rename(&aside, &folder).unwrap();
        } else {
            std::fs::remove_dir_all(&folder).unwrap();
            e.run();
            assert_eq!(e.program(EDITOR).presence(), v1::Presence::Gone);
            e.put(main, "start();\n");
        }
        e.run();
        let back = e.program(EDITOR);
        assert_eq!(back.presence(), v1::Presence::Held, "{how}");
        assert!(back.findings.is_empty(), "{how}: {:?}", back.findings);
        append(&e, main, "steal();\n");
        e.run();
        for what in EDITOR_ASKED {
            let k = e.program(what);
            assert_eq!(k.presence(), v1::Presence::Held, "{how} {what}");
            assert_eq!(rules_of(&k), ["integrity.app-code-outside"], "{how} {what}");
            assert_eq!(
                code_reading(&k).completeness(),
                v1::Completeness::Full,
                "{how} {what}"
            );
        }
    }
}

/// An application that deletes its folder of code and writes it again unchanged in content, as
/// some do at every quit and start, raises nothing however many times it does so.
#[test]
fn a_code_folder_deleted_and_written_again_unchanged_raises_nothing() {
    let e = Estate::new("program-folder-cycles");
    e.app("Editor.app", "org.example.editor", "3.0");
    let main = "home/Library/Application Support/Editor/main.js";
    e.put(main, "start();\n");
    e.run();
    for cycle in 0..3 {
        std::fs::remove_dir_all(e.home().join("Library/Application Support/Editor")).unwrap();
        e.run();
        e.put(main, "start();\n");
        e.run();
        let k = e.program(EDITOR);
        assert_eq!(k.presence(), v1::Presence::Held, "{cycle}");
        assert!(k.findings.is_empty(), "{cycle}: {:?}", k.findings);
    }
}

/// The promise against false calm, for a store that holds one folder under two spellings of its
/// name, as a build that named folders by their spelling on disk could leave: the spelling in
/// force is kept, and with none in force the one retracted last, so the folder on disk is never
/// retracted to be added again under a stale spelling, and a change to it is found.
#[test]
fn of_two_stored_spellings_of_a_folder_the_one_in_force_and_then_the_one_retracted_last_is_kept() {
    let stale = "file:machine:mac/Library/Application Support/editor";
    // A stale spelling, retracted at a time given here, copied from what the store holds of the
    // folder now.
    let copy = |e: &Estate, layer: &str, retracted_at: i64| {
        let db = rusqlite::Connection::open(e.store()).unwrap();
        db.execute(
            "INSERT OR IGNORE INTO entity (id, type) VALUES (?1, 'file')",
            [stale],
        )
        .unwrap();
        db.execute(
            "INSERT INTO assertion (layer, subject, predicate, object, reader, scope, kind,
                                    source_ref, basis, observed_at, run_id, retracted_at,
                                    retracted_by)
             SELECT 'retracted', ?1, predicate,
                    CASE predicate WHEN 'has_version' THEN '0.9' ELSE object END,
                    reader, scope, kind, source_ref, basis, observed_at, run_id, ?3, run_id
             FROM assertion WHERE subject = ?2 AND layer = ?4",
            rusqlite::params![stale, EDITOR_FOLDER, retracted_at, layer],
        )
        .unwrap();
    };
    for case in ["one in force", "both retracted"] {
        let e = Estate::new("program-folder-spellings");
        e.app("Editor.app", "org.example.editor", "3.0");
        let main = "home/Library/Application Support/Editor/main.js";
        e.put(main, "start();\n");
        e.run();
        if case == "one in force" {
            // Retracted later than anything in force was written, and with the id that sorts
            // after the one in force.
            copy(&e, "live", i64::from(i32::MAX));
            append(&e, main, "steal();\n");
            e.run();
            assert_eq!(
                rules_of(&e.program(EDITOR)),
                ["integrity.app-code-outside"],
                "{case}"
            );
        } else {
            // Retracted before the spelling on disk was last retracted, and after one of its
            // facts was: the last retraction counts, not the first.
            copy(&e, "live", 500);
            std::fs::remove_dir_all(e.home().join("Library/Application Support/Editor")).unwrap();
            e.run();
            rusqlite::Connection::open(e.store())
                .unwrap()
                .execute(
                    "UPDATE assertion SET retracted_at = 100
                     WHERE subject = ?1 AND predicate = 'located_on'",
                    [EDITOR_FOLDER],
                )
                .unwrap();
            e.put(main, "start();\n");
            e.run();
        }
        let k = e.program(EDITOR);
        assert!(has_fact(&k, EDITOR_FOLDER, "has_digest"), "{case}");
        assert!(!has_fact(&k, stale, "has_digest"), "{case}");
    }
}

/// A folder of code with no code left in it once its application was removed is let go, as an
/// uninstaller that leaves a settings file behind leaves it: no finding, and the application is
/// `gone`. While the application is installed, code removed from its folder is a change, as
/// before.
#[test]
fn a_code_folder_with_no_code_left_after_its_application_went_is_let_go() {
    for removed in [true, false] {
        let e = Estate::new("program-folder-no-code");
        e.app("Editor.app", "org.example.editor", "3.0");
        let main = "home/Library/Application Support/Editor/main.js";
        e.put(main, "start();\n");
        e.put(
            "home/Library/Application Support/Editor/settings.json",
            "{}\n",
        );
        e.run();
        if removed {
            std::fs::remove_dir_all(e.0.join("system/Applications/Editor.app")).unwrap();
        }
        std::fs::remove_file(e.0.join(main)).unwrap();
        e.run();
        let k = e.program(EDITOR);
        assert_eq!(code_reading(&k).completeness(), v1::Completeness::Full);
        if removed {
            assert_eq!(k.presence(), v1::Presence::Gone);
            assert!(k.findings.is_empty(), "{:?}", k.findings);
        } else {
            assert_eq!(k.presence(), v1::Presence::Held);
            assert_eq!(rules_of(&k), ["integrity.app-code-outside"]);
        }
    }
}

/// The promise against false calm, for a folder of code renamed to another Unicode form of its
/// name: on a Mac's volume it is the same folder, so it stays held under the name the store gives
/// it, and a change made with the rename raises the finding.
#[test]
fn a_held_code_folder_renamed_to_another_unicode_form_stays_held_and_its_change_is_found() {
    let e = Estate::new("program-folder-nfd");
    let nfc = "Caf\u{e9}";
    let nfd = "Cafe\u{301}";
    e.app(&format!("{nfc}.app"), "org.example.cafe", "1.0");
    let main = format!("home/Library/Application Support/{nfc}/main.js");
    e.put(&main, "start();\n");
    e.run();
    std::fs::remove_dir_all(e.0.join(format!("system/Applications/{nfc}.app"))).unwrap();
    e.run();
    let support = e.home().join("Library/Application Support");
    std::fs::rename(support.join(nfc), support.join(nfd)).unwrap();
    append(
        &e,
        &format!("home/Library/Application Support/{nfd}/main.js"),
        "steal();\n",
    );
    e.run();
    for what in [
        "org.example.cafe".to_string(),
        format!("~/Library/Application Support/{nfd}"),
        format!("~/Library/Application Support/{nfc}"),
    ] {
        let k = e.program(&what);
        assert_eq!(k.presence(), v1::Presence::Held, "{what}");
        assert_eq!(
            thing(&k),
            "component:machine:mac/macos-app/org.example.cafe",
            "{what}"
        );
        assert_eq!(rules_of(&k), ["integrity.app-code-outside"], "{what}");
    }
}

/// An application and its folder of code named in two Unicode forms of one name are one
/// program, as they are one name on a Mac's volume: the folder is read as its, a change to it is
/// found in the application's answer, and once the bundle is removed the folder still holds it.
#[test]
fn an_application_and_its_folder_named_in_two_unicode_forms_are_one_program() {
    let (nfc, nfd) = ("Caf\u{e9}", "Cafe\u{301}");
    for (app, folder) in [(nfc, nfd), (nfd, nfc)] {
        let e = Estate::new("program-folder-forms");
        e.app(&format!("{app}.app"), "org.example.cafe", "1.0");
        let main = format!("home/Library/Application Support/{folder}/main.js");
        e.put(&main, "start();\n");
        e.run();
        append(&e, &main, "steal();\n");
        e.run();
        let id = "component:machine:mac/macos-app/org.example.cafe";
        let k = e.program(id);
        assert_eq!(k.same_as.len(), 1, "{app:?}: {:?}", k.same_as);
        assert_eq!(rules_of(&k), ["integrity.app-code-outside"], "{app:?}");
        std::fs::remove_dir_all(e.0.join(format!("system/Applications/{app}.app"))).unwrap();
        e.run();
        assert_eq!(e.program(id).presence(), v1::Presence::Held, "{app:?}");
    }
}

/// On an ordinary Mac nothing changes: an application installed, updated with its code, removed
/// with its folder, or removed with it and installed again at another version reads exactly as
/// before, with the reading of applications' code full, no folder named as held without a
/// matching application, and no finding.
#[test]
fn an_application_installed_updated_or_removed_with_its_folder_reads_as_before() {
    for case in ["installed", "updated", "removed", "installed again"] {
        let e = Estate::new(&format!("program-folder-ordinary-{case}"));
        e.app("Editor.app", "org.example.editor", "3.0");
        e.put(
            "home/Library/Application Support/Editor/main.js",
            "start();\n",
        );
        e.run();
        match case {
            "updated" => {
                append(
                    &e,
                    "home/Library/Application Support/Editor/main.js",
                    "more();\n",
                );
                e.app("Editor.app", "org.example.editor", "3.1");
            }
            "removed" | "installed again" => {
                std::fs::remove_dir_all(e.0.join("system/Applications/Editor.app")).unwrap();
                std::fs::remove_dir_all(e.home().join("Library/Application Support/Editor"))
                    .unwrap();
                if case == "installed again" {
                    e.run();
                    e.app("Editor.app", "org.example.editor", "4.0");
                    e.put(
                        "home/Library/Application Support/Editor/main.js",
                        "start();\n",
                    );
                }
            }
            _ => {}
        }
        e.run();
        let k = e.program("org.example.editor");
        let expected = if case == "removed" {
            v1::Presence::Gone
        } else {
            v1::Presence::Held
        };
        assert_eq!(k.presence(), expected, "{case}");
        assert!(k.findings.is_empty(), "{case}: {:?}", k.findings);
        let code = code_reading(&k);
        assert_eq!(code.completeness(), v1::Completeness::Full, "{case}");
        assert!(
            !code
                .reason_text
                .as_deref()
                .is_some_and(|r| r.contains("still compared")),
            "{case}: {:?}",
            code.reason_text
        );
    }
}

/// Two applications whose bundles share a folder name, and so match one folder of code, are two
/// programs: neither is in the other's answer and a finding about one is not the other's. The
/// one removed is not gone while the folder that matches it is held: the store does not keep
/// which application the reading matched it to, and a program is held while any unit is. A formula of a tap and the core
/// formula of the same short name are two programs too: a keg is its own formula's, and one whose
/// version Homebrew gave for no formula of its name stays tied to that name.
#[test]
fn a_program_is_tied_to_its_own_parts_and_never_through_them_to_another_program() {
    let e = Estate::new("program-own-parts");
    e.app("Editor.app", "org.example.editor", "3.0");
    e.app_in(
        "home/Applications",
        "Editor.app",
        "org.example.other",
        "1.0",
    );
    e.put(
        "home/Library/Application Support/Editor/main.js",
        "start();\n",
    );
    e.formula("tool", "1.0");
    e.put("system/opt/homebrew/Cellar/odd/3.0/bin/odd", "invented\n");
    e.put(
        "brew.json",
        r#"{"formulae": [{"full_name": "tool", "tap": "homebrew/core", "installed": [{"version": "1.0"}]}, {"full_name": "example/tap/tool", "tap": "example/tap", "installed": [{"version": "2.0"}]}, {"full_name": "odd", "tap": "homebrew/core", "installed": [{"version": "2.0"}]}], "casks": []}"#,
    );
    e.run();
    {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(e.0.join("system/opt/homebrew/Cellar/tool/1.0/bin/tool"))
            .unwrap();
        f.write_all(b"steal();\n").unwrap();
    }
    e.run();
    let folder = "file:machine:mac/Library/Application Support/Editor";
    let one = "component:machine:mac/macos-app/org.example.editor";
    let other = "component:machine:mac/macos-app/org.example.other";
    let ids =
        |k: &v1::Known| -> Vec<String> { k.same_as.iter().map(|s| s.id_text.clone()).collect() };
    assert_eq!(ids(&e.program(one)), [folder]);
    assert_eq!(ids(&e.program(other)), [folder]);
    // The other removed: held by the folder, which may be its, and still not in the first's answer.
    std::fs::remove_dir_all(e.0.join("home/Applications/Editor.app")).unwrap();
    e.run();
    assert_eq!(e.program(other).presence(), v1::Presence::Held);
    assert_eq!(e.program(one).presence(), v1::Presence::Held);
    assert_eq!(ids(&e.program(one)), [folder]);
    // The keg of version 1.0 is the core formula's, not the tap's.
    let core = e.program("component:machine:mac/brew/tool");
    assert_eq!(ids(&core), [KEG]);
    assert_eq!(core.findings.len(), 1, "{:?}", core.findings);
    let tap = e.program("component:machine:mac/brew/example/tap/tool");
    assert!(ids(&tap).is_empty(), "{:?}", ids(&tap));
    assert!(tap.findings.is_empty(), "{:?}", tap.findings);
    assert_eq!(
        ids(&e.program("component:machine:mac/brew/odd")),
        ["file:machine:mac//opt/homebrew/Cellar/odd/3.0"]
    );
}

/// A name that fits more than one program is not answered for one of them: the command fails as
/// a misuse and names every program it fits by id, and each id then answers for its program.
#[test]
fn a_name_that_fits_two_programs_is_refused_with_their_ids() {
    let e = Estate::new("program-two");
    e.formula("tool", "1.0");
    e.package("tool", "3.1.0");
    e.run();
    let out = e.ask("program", Some("tool"), &[]);
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty());
    let said = String::from_utf8_lossy(&out.stderr);
    let ids = [
        "component:machine:mac/brew/tool",
        "component:machine:mac/npm/tool",
    ];
    assert!(ids.iter().all(|id| said.contains(id)), "{said}");
    let out = e.ask("program", Some("tool"), &["--json"]);
    assert_eq!(out.status.code(), Some(2));
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    let error = &v["errors"][0];
    assert_eq!(
        (&v["ok"], &v["operation"], &error["code"]),
        (
            &Value::Bool(false),
            &Value::from("program"),
            &Value::from("several_programs")
        )
    );
    // A refusal is never read as an answer: it has no format.
    assert!(v.get("format").is_none());
    assert_eq!(error["ids_text"], serde_json::json!(ids));
    for id in ids {
        assert_eq!(thing(&e.program(id)), id);
    }
}

/// A program that was removed is gone, not unknown, asked by its old path or by its name; and an
/// id the store holds that no reading of programs wrote about is refused, not answered as a
/// program the store never heard of.
#[test]
fn a_removed_program_is_gone_and_an_id_that_is_not_a_program_is_refused() {
    let e = Estate::new("program-gone");
    e.app("Tiny.app", "org.example.tiny", "2.0");
    e.checkout("dev/shop");
    e.run();
    std::fs::remove_dir_all(e.0.join("system/Applications/Tiny.app")).unwrap();
    e.run();
    for what in ["/Applications/Tiny.app", "org.example.tiny"] {
        let k = e.program(what);
        assert_eq!(k.presence(), v1::Presence::Gone, "{what}");
        assert_eq!(thing(&k), TINY);
        assert!(k.facts.is_empty());
        // The reading that wrote about it speaks for it.
        assert_eq!(readings(&k)[0].1, BUNDLES);
    }
    let out = e.ask(
        "program",
        Some("checkout:machine:mac/dev/shop"),
        &["--json"],
    );
    assert_eq!(out.status.code(), Some(2));
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["errors"][0]["code"], "not_a_program");
}

/// The promise against false calm, for a machine: one the store never heard of, one whose
/// readings were all full, and one known whose sweep did not complete are three different
/// answers. The unknown one carries the readings that find machines.
#[test]
fn unknown_known_and_read_in_full_and_known_but_not_read_are_three_different_machine_answers() {
    let e = Estate::new("machine-three");
    e.put("home/.ssh/config", "Host web\nHost cut\n");
    e.put("servers/web.txt", &server("dpkg\n", BASH));
    let full = server("dpkg\n", BASH);
    e.put("servers/cut.txt", &full[..full.find("bash").unwrap()]);
    e.run();

    let unknown = e.machine(Some("ghost"));
    assert_eq!(unknown.presence(), v1::Presence::Unknown);
    assert_eq!(unknown.thing, None);
    assert_eq!(
        readings(&unknown),
        [
            (
                "known-hosts",
                "known hosts",
                "machine:mac",
                v1::Completeness::Full
            ),
            (
                "ssh-config",
                "ssh configuration",
                "machine:mac",
                v1::Completeness::Full
            ),
            (
                "tailnet",
                "tailnet peers",
                "machine:mac",
                v1::Completeness::Full
            ),
        ]
    );

    let quiet = e.machine(Some("web"));
    assert_eq!(quiet.presence(), v1::Presence::Held);
    assert_eq!(thing(&quiet), "machine:web");
    assert!(all_full(&quiet), "{:?}", readings(&quiet));
    let own: Vec<&str> = readings(&quiet)
        .into_iter()
        .filter(|r| r.2 == "machine:web")
        .map(|r| r.1)
        .collect();
    assert!(own.contains(&"system packages") && own.contains(&"sweep visit"));

    let not_read = e.machine(Some("cut"));
    assert_eq!(not_read.presence(), v1::Presence::Held);
    let packages = not_read
        .coverage
        .iter()
        .find(|c| c.kind == "system packages")
        .unwrap();
    assert_eq!(
        (packages.scope_text.as_str(), packages.completeness()),
        ("machine:cut", v1::Completeness::None)
    );
    assert_eq!(
        packages.reason_text.as_deref(),
        Some("the sweep of this server did not complete")
    );
}

/// The reading a never-swept server carries, made by rule: no visit, nothing read on it.
fn never_visited(k: &v1::Known) -> Option<&v1::Coverage> {
    k.coverage
        .iter()
        .find(|c| c.reader == "servers" && c.kind == "sweep visit" && c.observed_at.is_none())
}

/// The promise against false calm for a server known only by its name: the server check never
/// visited it, so its answer carries a reading of that visit that is not full, and is never all
/// full. A server that was swept has no such reading, and neither does one swept under another
/// of its ids that the resolver links, nor this Mac.
#[test]
fn a_server_never_swept_carries_a_reading_that_is_not_full_and_a_swept_one_does_not() {
    let e = Estate::new("machine-never");
    e.put(
        "home/.ssh/config",
        "Host web\n  HostName web.example.org\nHost vault\nHost db\n",
    );
    // The same server known to known hosts by its full name: one machine under two ids.
    e.put(
        "home/.ssh/known_hosts",
        "web.example.org ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIInventedInventedInventedInventedInvented0\n",
    );
    e.put("servers/web.txt", &server("dpkg\n", BASH));
    e.run();

    let never = e.machine(Some("vault"));
    assert_eq!(never.presence(), v1::Presence::Held);
    assert!(!all_full(&never));
    let visit = never_visited(&never).unwrap();
    assert_eq!(
        (
            visit.scope_text.as_str(),
            visit.completeness(),
            visit.cause(),
            visit.reason_text.as_deref(),
        ),
        (
            "machine:vault",
            v1::Completeness::None,
            v1::Cause::NotGiven,
            Some("the server check has never visited this machine, so nothing on it was read")
        )
    );
    assert!(visit.lacks.is_empty());
    // In its place in the order of scope, reader and kind, whether its id sorts after this
    // Mac's, as `vault` does, or before, as `db` does.
    for k in [&never, &e.machine(Some("db"))] {
        let order: Vec<(&str, &str, &str)> = k
            .coverage
            .iter()
            .map(|c| (c.scope_text.as_str(), c.reader.as_str(), c.kind.as_str()))
            .collect();
        assert!(order.is_sorted(), "{order:?}");
        assert_eq!(order.len(), 2, "{order:?}");
    }
    assert_eq!(
        e.machine(Some("machine:vault")).coverage,
        never.coverage,
        "asked by its id"
    );

    let swept = e.machine(Some("web"));
    assert!(never_visited(&swept).is_none());
    assert!(all_full(&swept));
    // Swept as `web`, asked by the name known hosts gives it: not "never visited".
    let other_id = e.machine(Some("web.example.org"));
    assert_eq!(thing(&other_id), "machine:web.example.org");
    assert!(never_visited(&other_id).is_none());
    // This Mac is not a server the check visits.
    assert!(
        e.machine(None)
            .coverage
            .iter()
            .all(|c| c.reader != "servers")
    );
    // A machine the store never heard of gets nothing new.
    assert!(never_visited(&e.machine(Some("ghost"))).is_none());
}

/// A machine the store knows under several ids is one machine: asked by any name it is known by,
/// the answer gives what was read of it under every one of them. Here the sweep read it as
/// `web` and known hosts know it as `web.example.org`; the answers differ only in what was
/// asked and which id is named.
#[test]
fn a_machine_asked_by_any_name_it_is_known_by_gives_what_was_read_of_it() {
    let e = Estate::new("machine-names");
    e.put("home/.ssh/config", "Host web\n  HostName web.example.org\n");
    e.put(
        "home/.ssh/known_hosts",
        "web.example.org ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIInventedInventedInventedInventedInvented0\n",
    );
    e.put("servers/web.txt", &server("dpkg\n", BASH));
    e.run();
    let by_alias = e.machine(Some("web"));
    assert_eq!(thing(&by_alias), "machine:web");
    assert!(
        by_alias
            .parts
            .iter()
            .any(|p| p.id_text == "component:machine:web/deb/bash")
    );
    assert!(
        by_alias
            .facts
            .iter()
            .any(|f| f.subject_text == "machine:web"
                && f.predicate == "same_as"
                && f.object_text == "machine:web.example.org")
    );
    // What known hosts read under the other id is in it, with the id it is about.
    assert!(has_fact(&by_alias, "machine:web.example.org", "known_as"));
    assert!(by_alias.coverage.iter().any(|c| c.reader == "known-hosts"));
    // Its other ids are named, so a fact under one is told from a fact about something else.
    let ids =
        |k: &v1::Known| -> Vec<String> { k.same_as.iter().map(|e| e.id_text.clone()).collect() };
    assert_eq!(ids(&by_alias), ["machine:web.example.org"]);
    assert_eq!(by_alias.question(), v1::Question::Machine);
    for (what, id, same_as) in [
        ("web.example.org", "machine:web.example.org", "machine:web"),
        (
            "machine:web.example.org",
            "machine:web.example.org",
            "machine:web",
        ),
        ("machine:web", "machine:web", "machine:web.example.org"),
    ] {
        let mut other = e.machine(Some(what));
        assert_eq!(thing(&other), id, "{what}");
        assert_eq!(other.asked_text, what);
        assert_eq!(ids(&other), [same_as], "{what}");
        other.asked_text = by_alias.asked_text.clone();
        other.thing = by_alias.thing.clone();
        other.same_as = by_alias.same_as.clone();
        other.answered_at = by_alias.answered_at;
        assert_eq!(other, by_alias, "{what}");
    }
}

/// A machine the store knew and no longer names anywhere is gone, not unknown, asked by its name
/// or by its id: what was read of it is retracted, and the answer does not pass for one about a
/// machine never seen.
#[test]
fn a_machine_no_longer_named_is_gone_not_unknown() {
    let e = Estate::new("machine-gone");
    e.put(
        "home/.ssh/config",
        "Host old\n  HostName old.example.invalid\n",
    );
    e.run();
    e.put("home/.ssh/config", "Host web\n");
    e.run();
    for what in ["old", "machine:old"] {
        let k = e.machine(Some(what));
        assert_eq!(k.presence(), v1::Presence::Gone, "{what}");
        assert_eq!(thing(&k), "machine:old");
        assert!(k.facts.is_empty());
        // The reading that named it speaks for it, and nothing on it was ever read.
        assert!(readings(&k).iter().any(|r| r.0 == "ssh-config"));
        assert!(never_visited(&k).is_some());
    }
}

/// Another machine answers with what was read on it and what was not: its packages with their
/// versions, and the reading of packages partial for the package manager this build has no
/// reader for, named. Nothing of this Mac is in it.
#[test]
fn another_machine_answers_with_what_was_read_of_it_and_what_was_not() {
    let e = Estate::new("machine-other");
    e.put(
        "home/.ssh/config",
        "Host web\n  HostName web.example.invalid\n",
    );
    e.put("servers/web.txt", &server("dpkg\nrpm\n", BASH));
    e.formula("tool", "1.0");
    e.run();
    let k = e.machine(Some("web"));
    let bash = "component:machine:web/deb/bash";
    assert!(k.parts.iter().any(|p| p.id_text == bash));
    let version = k
        .facts
        .iter()
        .find(|f| f.subject_text == bash && f.predicate == "has_version")
        .unwrap();
    assert_eq!(version.object_text, "5.2.21-2ubuntu4");
    assert_eq!(version.assertions[0].reader, "servers");
    let packages = k
        .coverage
        .iter()
        .find(|c| c.kind == "system packages")
        .unwrap();
    assert_eq!(
        (packages.completeness(), packages.cause()),
        (v1::Completeness::Partial, v1::Cause::NoReader)
    );
    assert_eq!(packages.lacks[0].name_text.as_deref(), Some("rpm"));
    // The name it is known by, from the reading that named it on this Mac.
    let named = k
        .facts
        .iter()
        .find(|f| f.predicate == "known_as" && f.object_text == "web.example.invalid")
        .unwrap();
    assert_eq!(named.assertions[0].scope_text, "machine:mac");
    // Asked by that name, it is the same machine.
    assert_eq!(e.machine(Some("web.example.invalid")).facts, k.facts);
    // Nothing of this Mac: no reading of Homebrew, no package of it.
    assert!(k.coverage.iter().all(|c| c.reader != "brew"));
    assert!(
        k.parts
            .iter()
            .all(|p| p.id_text.starts_with("component:machine:web/"))
    );
}

/// A machine's parts are one level: a project on this Mac is a part, and what is inside the
/// project (its packages, its hooks) is not; the project's own question gives those. The
/// finding about a hook is the machine's all the same. With no argument the question is about
/// this Mac.
#[test]
fn a_machines_parts_are_one_level_and_a_project_on_it_is_a_part_without_its_own_parts() {
    let e = Estate::new("machine-level");
    e.checkout("dev/shop");
    e.put(
        "home/dev/shop/package-lock.json",
        "{\"name\": \"shop\", \"lockfileVersion\": 3, \"packages\": {\"\": {\"name\": \"shop\"}, \
         \"node_modules/left-pad\": {\"version\": \"1.3.0\"}}}\n",
    );
    e.formula("tool", "1.0");
    e.run();
    e.put("home/dev/shop/.git/hooks/pre-commit", "#!/bin/sh\nexit 0\n");
    e.run();

    let mac = e.machine(None);
    assert_eq!(thing(&mac), "machine:mac");
    // This Mac has no fact of its own here, and holds everything on it.
    assert_eq!(mac.presence(), v1::Presence::Held);
    assert!(mac.facts.iter().all(|f| f.subject_text != "machine:mac"));
    assert_eq!(e.machine(Some("mac")).parts, mac.parts);
    let shop = "checkout:machine:mac/dev/shop";
    let left_pad = "component:checkout:machine:mac/dev/shop/npm/left-pad";
    let hook = "file:machine:mac/dev/shop/.git/hooks/pre-commit";
    let parts: Vec<&str> = mac.parts.iter().map(|p| p.id_text.as_str()).collect();
    for part in [shop, KEG, "component:machine:mac/brew/tool"] {
        assert!(parts.contains(&part), "{part}: {parts:?}");
    }
    for deeper in [left_pad, hook] {
        assert!(!parts.contains(&deeper), "{deeper}");
        assert!(mac.facts.iter().all(|f| f.subject_text != deeper));
    }
    assert!(mac.findings.iter().any(|f| f.about_text == hook));

    let project = e.known("project", Some("~/dev/shop"));
    let inside: Vec<&str> = project.parts.iter().map(|p| p.id_text.as_str()).collect();
    assert!(inside.contains(&left_pad) && inside.contains(&hook));
    assert!(project.findings.iter().any(|f| f.about_text == hook));
}

/// The promise against false calm, for a machine: every finding the store holds about something
/// on it is in its answer, at any depth. A hook inside a project on it is two levels down, and a
/// place that could not be read is tied to it by no reading, only by its id; both are its.
#[test]
fn every_finding_about_something_on_a_machine_is_in_its_answer_at_any_depth() {
    use std::os::unix::fs::PermissionsExt;
    let e = Estate::new("machine-depth");
    e.checkout("dev/shop");
    let plugins = e.0.join("system/Library/Security/SecurityAgentPlugins");
    std::fs::create_dir_all(&plugins).unwrap();
    e.run();
    e.put("home/dev/shop/.git/hooks/pre-commit", "#!/bin/sh\nexit 0\n");
    std::fs::set_permissions(&plugins, std::fs::Permissions::from_mode(0o000)).unwrap();
    e.run();
    std::fs::set_permissions(&plugins, std::fs::Permissions::from_mode(0o755)).unwrap();

    let listed = e.json("findings", None);
    let mut all: Vec<String> = listed["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["finding"]["id"].as_str().unwrap().to_string())
        .collect();
    all.sort();
    let mac = e.machine(None);
    let mut mine: Vec<String> = mac.findings.iter().map(|f| f.id.clone()).collect();
    mine.sort();
    assert_eq!(mine, all);
    let about: Vec<&str> = mac.findings.iter().map(|f| f.about_text.as_str()).collect();
    for deep in [
        "file:machine:mac/dev/shop/.git/hooks/pre-commit",
        "file:machine:mac//Library/Security/SecurityAgentPlugins",
    ] {
        assert!(about.contains(&deep), "{deep}: {about:?}");
    }
}

/// A finding about a part a reading tied to the thing is in the thing's answer, however the
/// part's id is made, and whether the link is in force or retracted: here parts of an invented
/// type whose ids hold nothing of the machine's, one tied to it by a link since retracted, so it
/// is no longer among its parts, and one tied to that one by a link in force.
#[test]
fn a_finding_about_a_part_a_reading_tied_to_a_machine_is_in_its_answer_whatever_its_id() {
    let e = Estate::new("machine-links");
    e.run();
    let conn = rusqlite::Connection::open(e.store()).unwrap();
    let pick = |sql: &str| -> String { conn.query_row(sql, [], |r| r.get(0)).unwrap() };
    let kind = pick("SELECT name FROM coverage_kind ORDER BY name LIMIT 1");
    let basis = pick("SELECT name FROM basis_kind ORDER BY strength LIMIT 1");
    conn.execute_batch(
        "INSERT INTO entity_type VALUES ('gadget', 'used'), ('widget', 'used');
         INSERT INTO entity VALUES ('gadget:7f3a', 'gadget'), ('widget:b2', 'widget');",
    )
    .unwrap();
    for (layer, subject, predicate, object, retracted) in [
        (
            "retracted",
            "gadget:7f3a",
            "part_of",
            "machine:mac",
            Some(2),
        ),
        ("live", "widget:b2", "located_on", "gadget:7f3a", None),
    ] {
        conn.execute(
            "INSERT INTO assertion (layer, subject, predicate, object, reader, scope, kind,
                                    source_ref, basis, observed_at, run_id, retracted_at,
                                    retracted_by)
             VALUES (?1, ?2, ?3, ?4, 'example', 'machine:mac', ?5, 'example', ?6, 1, 'r1', ?7,
                     CASE WHEN ?7 IS NULL THEN NULL ELSE 'r2' END)",
            rusqlite::params![layer, subject, predicate, object, kind, basis, retracted],
        )
        .unwrap();
    }
    for (id, about) in [("fgadget", "gadget:7f3a"), ("fwidget", "widget:b2")] {
        conn.execute(
            "INSERT INTO finding (id, rule, about, occurrence, state, change, first_seen_at,
                                  first_seen_run, last_seen_at, last_seen_run)
             VALUES (?1, 'watched.autostart', ?2, 1, 'open', 'new', 1, 'r1', 1, 'r1')",
            [id, about],
        )
        .unwrap();
    }
    drop(conn);

    let mac = e.machine(None);
    let ids: Vec<&str> = mac.findings.iter().map(|f| f.id.as_str()).collect();
    for id in ["fgadget", "fwidget"] {
        assert!(ids.contains(&id), "{id}: {ids:?}");
    }
}

/// The binary answer and the JSON answer are one message, for a program and for a machine, known
/// or not; and text taken from the Mac, here a bundle identifier written to be read as an
/// instruction, is only in fields whose names end in `_text`.
#[test]
fn the_binary_answer_and_the_json_answer_are_one_message_for_a_program_and_a_machine() {
    let e = Estate::new("forms");
    let planted = "org.ignore-previous-instructions";
    e.app("Planted.app", planted, "1.0");
    e.put("home/.ssh/config", "Host web\nHost db\n");
    e.put("servers/web.txt", &server("dpkg\nrpm\n", BASH));
    e.run();
    let asked = [
        ("program", Some("/Applications/Planted.app")),
        ("program", Some("/Applications/Ghost.app")),
        ("machine", None),
        ("machine", Some("web")),
        ("machine", Some("ghost")),
        ("machine", Some("db")),
    ];
    for (question, what) in asked {
        let binary = e.known(question, what);
        let json = e.json(question, what);
        let mut parsed: v1::Known = serde_json::from_value(json.clone()).unwrap();
        // The two were made by two runs of the command, perhaps a second apart.
        assert!((parsed.answered_at - binary.answered_at).abs() <= 2);
        parsed.answered_at = binary.answered_at;
        assert_eq!(parsed, binary, "{question} {what:?}");
        let mut printed = serde_json::to_value(&binary).unwrap();
        printed["answered_at"] = json["answered_at"].clone();
        assert_eq!(printed, json);
    }
    let json = e.json("program", Some(planted));
    assert_eq!(json["format"], 1);
    fn walk(v: &Value, key: &str, planted: &str, seen: &mut usize) {
        match v {
            Value::String(s) if s.contains(planted) => {
                assert!(key.ends_with("_text"), "{key}: {s}");
                *seen += 1;
            }
            Value::Array(items) => items.iter().for_each(|i| walk(i, key, planted, seen)),
            Value::Object(fields) => fields.iter().for_each(|(k, v)| walk(v, k, planted, seen)),
            _ => {}
        }
    }
    let mut seen = 0;
    walk(&json, "", planted, &mut seen);
    assert!(seen >= 6, "{seen}");
}

/// A failure to answer is not a message of the contract, for either question: no store, a name
/// that fits several machines not known to be one, and too many words are failures with the
/// report commands' exit codes, nothing on stdout in binary and the failure envelope in JSON.
#[test]
fn a_failure_to_answer_a_program_or_a_machine_is_not_a_message_of_the_contract() {
    let e = Estate::new("failure");
    for question in ["program", "machine"] {
        let out = e.ask(question, Some("web"), &[]);
        assert_eq!(out.status.code(), Some(3), "{question}");
        assert!(out.stdout.is_empty());
        let out = e.ask(question, Some("web"), &["--json"]);
        let v: Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(
            (&v["operation"], &v["errors"][0]["code"]),
            (&Value::from(question), &Value::from("store_unreadable"))
        );
        let out = e.ask(question, Some("web"), &["db", "--json"]);
        assert_eq!(out.status.code(), Some(2));
        let usage: Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(usage["errors"][0]["code"], "usage");
        // Parsed as an answer all the same, neither failure is one: it reads as format 0.
        for v in [v, usage] {
            assert!(v.get("format").is_none(), "{v}");
            let parsed: v1::Known = serde_json::from_value(v).unwrap();
            assert_eq!(parsed.format, 0);
        }
    }
    // Two servers that call themselves by the same bare name are not known to be one machine.
    for (alias, address) in [("a", "203.0.113.10"), ("b", "203.0.113.20")] {
        let file = server("dpkg\n", BASH).replace(
            "##os\n",
            &format!("##names\nubuntu\n##addresses\neth0\t{address}/24\n##os\n"),
        );
        e.put(&format!("servers/{alias}.txt"), &file);
    }
    e.run();
    let out = e.ask("machine", Some("ubuntu"), &[]);
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty());
    let out = e.ask("machine", Some("ubuntu"), &["--json"]);
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["errors"][0]["code"], "several_machines");
    assert_eq!(
        v["errors"][0]["ids_text"],
        serde_json::json!(["machine:a", "machine:b"])
    );
}

/// The reading made by rule that says no reading looks at the place asked about.
fn unread(k: &v1::Known) -> Option<&v1::Coverage> {
    k.coverage
        .iter()
        .find(|c| c.reader == "immunity" && c.kind != LIMIT)
}

/// The reading made by rule that every answer `unknown` carries: other package managers are
/// not read.
const LIMIT: &str = "software of package managers this version does not look for";

/// A refusal of a question: exit 2, no format, and the envelope's error.
fn refused(e: &Estate, question: &str, what: &str) -> Value {
    let out = e.ask(question, Some(what), &["--json"]);
    assert_eq!(out.status.code(), Some(2), "{what}");
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(v.get("format").is_none(), "{v}");
    v["errors"][0].clone()
}

/// The promise against false calm for a path under no program the store holds: a tool in
/// `/usr/local/bin`, an application in `/Users/Shared`, in `~/Downloads`, two folders down in
/// `/Applications`, or one a reading would look at, answers `unknown` with a reading made by rule
/// that is not full, since the store does not keep where the readings looked; in `~/Downloads`
/// also with the reading that says the folder was not looked into.
#[test]
fn a_program_path_no_reading_looks_at_is_never_unknown_with_every_reading_full() {
    let e = Estate::new("program-unread");
    // A folder macOS asks permission for, which the walk names as not looked into.
    std::fs::create_dir_all(e.home().join("Downloads")).unwrap();
    e.run();
    for asked in [
        "/usr/local/bin/tool",
        "/Users/Shared/Tool.app",
        "~/Downloads/Tool.app",
        "/Applications/Suite/Extra/Tool.app",
        "/ApplicationsExtra/Tool.app",
        "/Applications/Ghost.app",
        "/Applications/Suite/Ghost.app/Contents/MacOS/Ghost",
        "~/Applications/Ghost.app",
        "/opt/homebrew/Cellar/ghost/1.0",
        "/usr/local/lib/node_modules/ghost",
    ] {
        let k = e.program(asked);
        assert_eq!(k.presence(), v1::Presence::Unknown, "{asked}");
        assert!(!all_full(&k), "{asked}");
        let rule = unread(&k).unwrap();
        assert_eq!(
            (
                rule.kind.as_str(),
                rule.scope_text.as_str(),
                rule.completeness(),
                rule.cause(),
                rule.observed_at
            ),
            (
                "places the readings that find programs look in",
                "machine:mac",
                v1::Completeness::None,
                v1::Cause::NotGiven,
                None
            ),
            "{asked}"
        );
    }
    let downloads = e.program("~/Downloads/Tool.app");
    assert!(downloads.coverage.iter().any(|c| {
        c.kind == "folders macOS asks permission for"
            && c.reason_text.as_deref() == Some("not looked into: ~/Downloads")
    }));
}

/// A program that moved away is still the program at the folder it left: one of two copies of
/// an application with the same identifier moved out of `/Applications`, and its old path answers
/// for the application, not `unknown`. A program that is at that path now answers instead.
#[test]
fn a_program_that_moved_answers_at_the_folder_it_left() {
    let e = Estate::new("program-moved");
    e.app("Tiny.app", "org.example.tiny", "2.0");
    e.app_in("home/Applications", "Tiny.app", "org.example.tiny", "1.0");
    e.run();
    std::fs::create_dir_all(e.0.join("system/Users/Shared")).unwrap();
    std::fs::rename(
        e.0.join("system/Applications/Tiny.app"),
        e.0.join("system/Users/Shared/Tiny.app"),
    )
    .unwrap();
    e.run();
    let left = e.program("/Applications/Tiny.app");
    assert_eq!(left.presence(), v1::Presence::Held);
    assert_eq!(thing(&left), TINY);
    e.app("Tiny.app", "org.example.other", "1.0");
    e.run();
    assert_eq!(
        thing(&e.program("/Applications/Tiny.app")),
        "component:machine:mac/macos-app/org.example.other"
    );
}

/// An id holding a hidden character is shown escaped, and given back as shown it asks for the
/// same program and the same machine.
#[test]
fn an_id_with_a_hidden_character_asks_back_the_same_program_and_machine() {
    let e = Estate::new("ask-back");
    e.app("Odd.app", "org.example.a\u{202e}b", "1.0");
    e.put("home/.ssh/config", "Host we\u{202e}b\n");
    e.run();
    let program = e.program("/Applications/Odd.app");
    assert_eq!(
        thing(&program),
        "component:machine:mac/macos-app/org.example.a\\u{202e}b"
    );
    let machine = e.machine(Some("we\u{202e}b"));
    assert_eq!(thing(&machine), "machine:we\\u{202e}b");
    assert_eq!(e.program(thing(&program)).thing, program.thing);
    assert_eq!(e.machine(Some(thing(&machine))).thing, machine.thing);
}

/// A program path the store knows only under another case answers for the program it knows,
/// with a reading made by rule that says it is spelled otherwise, never `unknown`: on a volume
/// that ignores case it is the same application.
#[test]
fn a_program_path_spelled_with_another_case_answers_for_the_program_and_says_so() {
    let e = Estate::new("program-case");
    e.app("Tiny.app", "org.example.tiny", "2.0");
    e.run();
    let k = e.program("/applications/tiny.app/Contents");
    assert_eq!(thing(&k), TINY);
    assert!(
        unread(&k).is_some_and(|c| c
            .reason_text
            .as_deref()
            .is_some_and(|r| r.starts_with("the path is spelled otherwise"))),
        "{:?}",
        k.coverage
    );
    assert!(!all_full(&k));
}

/// An id the store holds that is not a machine is refused, not answered as a machine never heard
/// of: a project, or a package on a server.
#[test]
fn an_id_that_is_not_a_machine_is_refused_not_unknown() {
    let e = Estate::new("machine-other-kind");
    e.put("home/.ssh/config", "Host web\n");
    e.put("servers/web.txt", &server("dpkg\n", BASH));
    e.checkout("dev/shop");
    e.run();
    for id in [
        "checkout:machine:mac/dev/shop",
        "component:machine:web/deb/bash",
    ] {
        let error = refused(&e, "machine", id);
        assert_eq!(error["code"], "not_a_machine", "{id}");
        assert_eq!(error["ids_text"], serde_json::json!([id]));
    }
}

/// The promise against false calm for a machine the owner set aside: it is no longer checked,
/// and its answer says so with a reading made by rule, naming what the owner said and the day,
/// and nothing of the owner's reason. Taking the statement back takes the reading away.
#[test]
fn a_machine_the_owner_set_aside_says_it_is_no_longer_checked() {
    let e = Estate::new("machine-aside");
    e.put("home/.ssh/config", "Host web\n");
    e.put("servers/web.txt", &server("dpkg\n", BASH));
    e.run();
    assert!(all_full(&e.machine(Some("web"))));
    let owner = |words: &[&str]| -> Value {
        let out = e
            .immunity()
            .arg("owner")
            .args(words)
            .args(["--json", "--store"])
            .arg(e.store())
            .arg("--tailscale")
            .arg(e.0.join("no-tailscale"))
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        serde_json::from_slice(&out.stdout).unwrap()
    };
    owner(&["web", "retired", "--reason", "invented reason"]);
    e.run();
    let k = e.machine(Some("web"));
    assert!(!all_full(&k));
    let aside = k
        .coverage
        .iter()
        .find(|c| c.kind == "sweep of a machine set aside by the owner")
        .unwrap();
    // The day the statement was made, as the list of statements gives its time.
    let made = owner(&[]);
    let at = made["statements"][0]["at"].as_i64().unwrap().to_string();
    let day = std::process::Command::new("/bin/date")
        .args(["-u", "-r", &at, "+%Y-%m-%d"])
        .output()
        .unwrap()
        .stdout;
    let day = String::from_utf8(day).unwrap().trim().to_string();
    assert_eq!(
        (
            aside.reader.as_str(),
            aside.scope_text.as_str(),
            aside.completeness(),
            aside.cause(),
            aside.observed_at,
            aside.reason_text.clone(),
        ),
        (
            "servers",
            "machine:web",
            v1::Completeness::None,
            v1::Cause::NotGiven,
            None,
            Some(format!(
                "the owner set this machine aside as retired on {day}, so the server check no longer visits it"
            )),
        )
    );
    owner(&["web", "withdraw"]);
    assert!(
        e.machine(Some("web"))
            .coverage
            .iter()
            .all(|c| c.kind != aside.kind)
    );
}

/// "Presence unknown" must not rest only on readings that were full: software MacPorts
/// installed is read by none of them, and the answer says so by the reading that names it.
#[test]
fn a_program_answer_rests_also_on_the_package_managers_no_reader_reads() {
    let e = Estate::new("program-managers");
    e.put("system/opt/local/bin/port", "");
    e.run();
    let unknown = e.program("invented-tool");
    assert_eq!(unknown.presence(), v1::Presence::Unknown);
    let managers = unknown
        .coverage
        .iter()
        .find(|c| c.kind == MANAGERS)
        .unwrap_or_else(|| panic!("{:?}", readings(&unknown)));
    assert_eq!(
        (managers.completeness(), managers.cause()),
        (v1::Completeness::None, v1::Cause::NoReader)
    );
    assert_eq!(managers.reason_text.as_deref(), Some("not read: MacPorts"));
}

#[test]
fn a_program_not_known_carries_the_limit_that_other_package_managers_are_not_read() {
    // The table of package managers names a few and is not complete. With none of them found
    // its reading is full, yet a program installed by volta, pipx, cargo install or another
    // manager is not found: "unknown" must say so, or it reads as "not on this Mac".
    let e = Estate::new("program-limit");
    e.run();
    let unknown = e.program("invented-tool");
    assert_eq!(unknown.presence(), v1::Presence::Unknown);
    let limit = unknown
        .coverage
        .iter()
        .find(|c| {
            c.reader == "immunity"
                && c.kind == "software of package managers this version does not look for"
        })
        .unwrap_or_else(|| panic!("{:?}", readings(&unknown)));
    assert_eq!(
        (limit.completeness(), limit.cause(), limit.observed_at),
        (v1::Completeness::None, v1::Cause::NoReader, None)
    );
    assert_eq!(
        limit.reason_text.as_deref(),
        Some(
            "software installed by a package manager other than Homebrew and npm is not checked, and Homebrew or Tailscale installed outside the places their installers use by default is not found"
        )
    );
    // The reading of the managers it looks for is full, and is not what carries it.
    let managers = unknown
        .coverage
        .iter()
        .find(|c| c.kind == MANAGERS)
        .unwrap();
    assert_eq!(managers.completeness(), v1::Completeness::Full);
}

/// The finding ids of an answer, in order.
fn finding_ids(k: &v1::Known) -> Vec<String> {
    let mut ids: Vec<String> = k.findings.iter().map(|f| f.id.clone()).collect();
    ids.sort();
    ids
}

/// An application whose name is not plain ASCII, its folder of code changed in place so that a
/// finding is about it, and a project of the same name with a finding of its own.
fn spelled_estate(tag: &str) -> Estate {
    let e = Estate::new(tag);
    e.app("Caf\u{e9}.app", "org.example.cafe", "1.0");
    e.put(
        "home/Library/Application Support/Caf\u{e9}/main.js",
        "start();\n",
    );
    e.checkout("dev/Caf\u{e9}");
    e.run();
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .open(e.0.join("home/Library/Application Support/Caf\u{e9}/main.js"))
        .unwrap();
    f.write_all(b"steal();\n").unwrap();
    e.put("home/dev/Caf\u{e9}/.git/hooks/pre-commit", "#!/bin/sh\n");
    e.run();
    e
}

/// The promise that an answer is about a unit the store holds however the place is spelled:
/// `..`, `.`, a doubled or a trailing slash, another case and another Unicode form, in a path and
/// in an id, give every command that takes a path or an id the same thing with the same findings.
/// A spelling the store does not hold as written says so with a reading that is not full.
#[test]
fn every_command_that_takes_a_path_answers_for_one_unit_however_the_place_is_spelled() {
    let e = spelled_estate("spelled-everywhere");
    let cafe = "Caf\u{e9}";
    let nfd = "Cafe\u{301}";
    for (question, base, id_form) in [
        (
            "program",
            format!("~/Library/Application Support/{cafe}"),
            format!("file:machine:mac/Library/Application Support/x/../{cafe}/"),
        ),
        (
            "project",
            format!("~/dev/{cafe}"),
            format!("checkout:machine:mac/dev/x/../{cafe}/"),
        ),
    ] {
        let first = e.known(question, Some(&base));
        let unit = first.thing.clone().unwrap();
        assert_eq!(first.findings.len(), 1, "{question}: {:?}", first.findings);
        let (up, last) = base.rsplit_once('/').unwrap();
        let written = [
            format!("{up}/x/../{last}"),
            format!("{up}/./{last}"),
            format!("{up}//{last}"),
            format!("{base}/"),
            format!("{base}//"),
            id_form,
        ];
        let otherwise = [
            format!("~/{}", base.trim_start_matches("~/").to_uppercase()),
            base.replace(cafe, nfd),
        ];
        let spellings = written
            .iter()
            .map(|w| (w, false))
            .chain(otherwise.iter().map(|w| (w, true)));
        for (what, spelled) in spellings {
            let k = e.known(question, Some(what));
            assert_eq!(k.thing.as_ref(), Some(&unit), "{question} {what:?}");
            assert_eq!(k.presence(), first.presence(), "{question} {what:?}");
            assert_eq!(finding_ids(&k), finding_ids(&first), "{question} {what:?}");
            let said = k.coverage.iter().any(|c| {
                c.reader == "immunity"
                    && c.reason_text
                        .as_deref()
                        .is_some_and(|r| r.starts_with("the path is spelled otherwise"))
            });
            assert_eq!(said, spelled, "{question} {what:?}");
        }
    }
}

/// The promise that findings are gathered before anything else: an answer never holds fewer
/// findings than the store has about the path asked, its unit and what lies inside it. A file in
/// a folder of code spelled in another case answers for its application with the finding; a
/// folder that holds that folder of code, or a project, answers `unknown` with the finding.
#[test]
fn an_answer_never_holds_fewer_findings_than_the_store_has_about_the_place_asked() {
    let e = spelled_estate("findings-first");
    let app = "component:machine:mac/macos-app/org.example.cafe";
    let by_app = e.program(app);
    assert_eq!(by_app.findings.len(), 1, "{:?}", by_app.findings);
    let inside = e.program("~/Library/Application Support/caf\u{c9}/main.js");
    assert_eq!(thing(&inside), app);
    assert_eq!(finding_ids(&inside), finding_ids(&by_app));
    assert!(!all_full(&inside));
    // Both reasons are said: spelled otherwise, and a single path inside.
    let reason = unread(&inside)
        .and_then(|c| c.reason_text.clone())
        .unwrap_or_default();
    assert!(
        reason.starts_with("the path is spelled otherwise")
            && reason.contains("a single path inside a program is not judged on its own"),
        "{reason}"
    );
    let holder = e.program("~/Library/Application Support");
    assert_eq!(holder.presence(), v1::Presence::Unknown);
    assert_eq!(finding_ids(&holder), finding_ids(&by_app));
    let projects = e.known("project", Some("~/dev"));
    assert_eq!(projects.presence(), v1::Presence::Unknown);
    let project = e.known("project", Some("~/dev/Caf\u{e9}"));
    assert_eq!(project.findings.len(), 1, "{:?}", project.findings);
    assert_eq!(finding_ids(&projects), finding_ids(&project));
}

/// The promise of a file inside a program: one its reading does not compare, a settings file or
/// compiled Python in a folder of code, is never answered with every reading full. It answers for
/// the program with a reading made by rule that a single path inside is not judged on its own.
#[test]
fn a_file_inside_a_program_is_never_answered_with_every_reading_full() {
    let e = Estate::new("program-file-inside");
    e.app("Editor.app", "org.example.editor", "3.0");
    e.put(
        "home/Library/Application Support/Editor/main.js",
        "start();\n",
    );
    e.put(
        "home/Library/Application Support/Editor/settings.json",
        "{}\n",
    );
    e.put(
        "home/Library/Application Support/Editor/lib/__pycache__/mod.cpython-312.pyc",
        "invented\n",
    );
    e.run();
    let whole = e.program("~/Library/Application Support/Editor");
    assert!(all_full(&whole), "{:?}", whole.coverage);
    for what in [
        "~/Library/Application Support/Editor/settings.json",
        "~/Library/Application Support/Editor/lib/__pycache__/mod.cpython-312.pyc",
    ] {
        let k = e.program(what);
        assert_eq!(
            thing(&k),
            "component:machine:mac/macos-app/org.example.editor",
            "{what}"
        );
        assert_eq!(k.presence(), v1::Presence::Held, "{what}");
        assert!(not_judged(&k), "{what}: {:?}", k.coverage);
        assert!(!all_full(&k), "{what}");
    }
}

/// The promise of presence, told in one place for every command: a program is held while any of
/// its units is, and `gone` needs the latest reading of every reading that owns one of its units
/// to be full. An application removed while the reading of applications' code was partial, its
/// folder of code kept as it was, is held and comes with that partial reading; once the folder
/// is gone too and that reading is full again, the application is gone.
#[test]
fn a_program_is_gone_only_when_every_reading_that_owns_one_of_its_units_was_full() {
    use std::os::unix::fs::PermissionsExt;
    let e = Estate::new("program-presence");
    e.app("Editor.app", "org.example.editor", "3.0");
    e.app("Other.app", "org.example.other", "1.0");
    e.put(
        "home/Library/Application Support/Editor/main.js",
        "start();\n",
    );
    e.put(
        "home/Library/Application Support/Other/main.js",
        "start();\n",
    );
    e.run();
    std::fs::remove_dir_all(e.0.join("system/Applications/Editor.app")).unwrap();
    // Another folder of code cannot be read: the reading of applications' code is partial.
    let shut = e.home().join("Library/Application Support/Other");
    std::fs::set_permissions(&shut, std::fs::Permissions::from_mode(0o000)).unwrap();
    e.run();
    std::fs::set_permissions(&shut, std::fs::Permissions::from_mode(0o755)).unwrap();
    let editor = "component:machine:mac/macos-app/org.example.editor";
    let code = "code kept by applications not signed by Apple under ~/Library/Application Support";
    for what in [
        editor,
        "/Applications/Editor.app",
        "~/Library/Application Support/Editor",
    ] {
        let k = e.program(what);
        assert_eq!(k.presence(), v1::Presence::Held, "{what}");
        assert!(
            k.coverage
                .iter()
                .any(|c| c.kind == code && c.completeness() == v1::Completeness::Partial),
            "{what}: {:?}",
            k.coverage
        );
    }
    // The folder goes too, and the reading is full again: the application is gone.
    std::fs::remove_dir_all(e.home().join("Library/Application Support/Editor")).unwrap();
    e.run();
    assert_eq!(e.program(editor).presence(), v1::Presence::Gone);
    // Gone, and then a reading that owns its folder of code is partial again: it cannot be told.
    std::fs::set_permissions(&shut, std::fs::Permissions::from_mode(0o000)).unwrap();
    e.run();
    std::fs::set_permissions(&shut, std::fs::Permissions::from_mode(0o755)).unwrap();
    let k = e.program(editor);
    assert_eq!(k.presence(), v1::Presence::Unknown);
    assert!(
        k.coverage
            .iter()
            .any(|c| c.kind == code && c.completeness() == v1::Completeness::Partial),
        "{:?}",
        k.coverage
    );
}

/// Writes an open finding about `about`, a file of this Mac the store may never have held.
fn finding_about(e: &Estate, id: &str, about: &str) {
    let conn = rusqlite::Connection::open(e.store()).unwrap();
    conn.execute(
        "INSERT OR IGNORE INTO entity (id, type) VALUES (?1, 'file')",
        [about],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO finding (id, rule, about, occurrence, state, change, first_seen_at,
                              first_seen_run, last_seen_at, last_seen_run)
         VALUES (?1, 'watched.autostart', ?2, 1, 'open', 'new', 1, 'r1', 1, 'r1')",
        [id, about],
    )
    .unwrap();
}

/// The reason of the reading made by rule for what was asked, if any.
fn rule_reason(k: &v1::Known) -> String {
    unread(k)
        .and_then(|c| c.reason_text.clone())
        .unwrap_or_default()
}

/// The promise of the one form at its edges: a slash after `~/` never leaves the home folder,
/// and the root and the home folder are folders that hold units, so asking about them says how
/// many lie inside and holds the findings about them.
#[test]
fn the_root_and_the_home_folder_hold_their_units_and_a_slash_after_home_never_leaves_it() {
    let e = Estate::new("edges");
    e.app("Tiny.app", "org.example.tiny", "2.0");
    e.checkout("dev/b");
    e.checkout("dev/c");
    e.run();
    finding_about(
        &e,
        "fapp",
        "file:machine:mac//Applications/Tiny.app/Contents/MacOS/Tiny",
    );
    finding_about(&e, "fproject", "file:machine:mac/dev/b/.vscode/tasks.json");
    let b = e.known("project", Some("~/dev/b"));
    for what in ["~//dev/b", "~///dev//b/"] {
        let k = e.known("project", Some(what));
        assert_eq!(k.thing, b.thing, "{what}");
    }
    let home = e.known("project", Some("~/"));
    assert_eq!(home.presence(), v1::Presence::Unknown);
    assert!(
        rule_reason(&home).contains("it holds 2 projects"),
        "{:?}",
        home.coverage
    );
    assert_eq!(finding_ids(&home), ["fproject"]);
    let root = e.program("/");
    assert_eq!(root.presence(), v1::Presence::Unknown);
    assert!(
        rule_reason(&root).contains("it holds 1 program"),
        "{:?}",
        root.coverage
    );
    assert_eq!(finding_ids(&root), ["fapp", "fproject"]);
}

/// The promise that a name and the machine an id names are compared by the key too: a program
/// asked by its name in another case, a machine asked by its id in another case, and a file or
/// a project of this Mac named under its machine in another case answer for what the store
/// holds, with its findings, and a match by the key alone says so.
#[test]
fn a_name_and_the_machine_of_an_id_spelled_otherwise_answer_for_what_the_store_holds() {
    let e = Estate::new("names-key");
    e.formula("tool", "1.0");
    e.app("Editor.app", "org.example.editor", "3.0");
    e.checkout("dev/b");
    e.put("home/.ssh/config", "Host example-host\n");
    e.run();
    finding_about(&e, "fkeg", KEG);
    finding_about(
        &e,
        "feditor",
        "file:machine:mac//Applications/Editor.app/Contents/Info.plist",
    );
    for (asked, written) in [
        ("TOOL", "tool"),
        ("ORG.EXAMPLE.EDITOR", "org.example.editor"),
        (
            "COMPONENT:machine:mac/macos-app/org.example.editor",
            "org.example.editor",
        ),
        (
            "file:machine:MAC//Applications/Editor.app",
            "org.example.editor",
        ),
    ] {
        let k = e.program(asked);
        let first = e.program(written);
        assert_eq!(k.thing, first.thing, "{asked}");
        assert!(!finding_ids(&k).is_empty(), "{asked}");
        assert_eq!(finding_ids(&k), finding_ids(&first), "{asked}");
        assert!(
            rule_reason(&k).contains("spelled otherwise"),
            "{asked}: {:?}",
            k.coverage
        );
        assert!(!all_full(&k), "{asked}");
    }
    let project = e.known("project", Some("checkout:machine:MAC/dev/b"));
    assert_eq!(thing(&project), "checkout:machine:mac/dev/b");
    assert!(rule_reason(&project).contains("spelled otherwise"));
    let host = e.machine(Some("machine:EXAMPLE-HOST"));
    assert_eq!(thing(&host), "machine:example-host");
}

/// The promise that an answer by name, by id and by path holds the same findings: those about
/// anything in a folder the program is or was installed at, whatever form it was asked in.
#[test]
fn a_program_asked_by_name_by_id_or_by_path_holds_the_same_findings() {
    let e = Estate::new("findings-any-form");
    e.formula("tool", "1.0");
    e.app("Editor.app", "org.example.editor", "3.0");
    e.run();
    finding_about(
        &e,
        "fbundle",
        "file:machine:mac//Applications/Editor.app/Contents/MacOS/Editor",
    );
    finding_about(&e, "fkeg", KEG);
    finding_about(
        &e,
        "fbin",
        "file:machine:mac//opt/homebrew/Cellar/tool/1.0/bin/tool",
    );
    for (forms, expected) in [
        (
            [
                "org.example.editor",
                "component:machine:mac/macos-app/org.example.editor",
                "/Applications/Editor.app",
            ],
            vec!["fbundle"],
        ),
        (
            [
                "tool",
                "component:machine:mac/brew/tool",
                "/opt/homebrew/Cellar/tool/1.0",
            ],
            vec!["fbin", "fkeg"],
        ),
    ] {
        for what in forms {
            assert_eq!(finding_ids(&e.program(what)), expected, "{what}");
        }
    }
}
