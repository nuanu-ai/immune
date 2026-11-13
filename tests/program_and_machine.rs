//! Promises of `immune program` and `immune machine`, the questions of the contract beside
//! `immune project`: what the store knows of one program installed on this Mac, and of one
//! machine, each as the same `Known` message. Each test runs the real binary over an invented
//! home folder, an invented system root and invented server files, so no test reads anything of
//! the Mac it runs on or asks the network.

use immune_contract::v1;
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
            "immune-questions-{tag}-{}-{nanos}",
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
    fn immune(&self) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_immune"));
        cmd.env("HOME", self.home()).current_dir(&self.0);
        cmd
    }

    /// `immune run` for the machine `mac` on this estate alone.
    fn run(&self) {
        let at = |name: &str| self.0.join(name);
        let out = self
            .immune()
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

    /// `immune <question> [<what>]` on this store, with these arguments after.
    fn ask(&self, question: &str, what: Option<&str>, extra: &[&str]) -> Output {
        self.immune()
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
        let _ = std::fs::remove_dir_all(&self.0);
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
            ("immune", LIMIT),
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
/// a global package's folder gives the package. No path is looked at on disk.
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
            (&same.thing, &same.facts, &same.coverage),
            (&by_bundle.thing, &by_bundle.facts, &by_bundle.coverage),
            "{what}"
        );
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
/// project (its packages, its hooks, the finding about a hook) is not; the project's own
/// question gives those. With no argument the question is about this Mac.
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
    assert!(mac.findings.iter().all(|f| f.about_text != hook));

    let project = e.known("project", Some("~/dev/shop"));
    let inside: Vec<&str> = project.parts.iter().map(|p| p.id_text.as_str()).collect();
    assert!(inside.contains(&left_pad) && inside.contains(&hook));
    assert!(project.findings.iter().any(|f| f.about_text == hook));
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
        .find(|c| c.reader == "immune" && c.kind != LIMIT)
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

/// The promise against false calm for a program in a place no reading looks at: a tool in
/// `/usr/local/bin`, an application in `/Users/Shared`, in `~/Downloads` or two folders down in
/// `/Applications` answers `unknown` with a reading made by rule that is not full, and in
/// `~/Downloads` with the reading that says the folder was not looked into. A path a reading
/// looks at has no such reading.
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
    for asked in [
        "/Applications/Ghost.app",
        "/Applications/Suite/Ghost.app/Contents/MacOS/Ghost",
        "~/Applications/Ghost.app",
        "/opt/homebrew/Cellar/ghost/1.0",
        "/usr/local/lib/node_modules/ghost",
    ] {
        let k = e.program(asked);
        // Every reading full but the standing limit that an answer `unknown` carries.
        assert!(unread(&k).is_none(), "{asked}");
        assert!(
            k.coverage
                .iter()
                .all(|c| c.kind == LIMIT || c.completeness() == v1::Completeness::Full),
            "{asked}"
        );
    }
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

/// A program path the store knows only under another case is refused with the ids it knows,
/// never answered `unknown`: on a volume that ignores case it may be the same application.
#[test]
fn a_program_path_spelled_with_another_case_is_refused_not_unknown() {
    let e = Estate::new("program-case");
    e.app("Tiny.app", "org.example.tiny", "2.0");
    e.run();
    let error = refused(&e, "program", "/applications/tiny.app/Contents");
    assert_eq!(error["code"], "spelled_otherwise");
    assert_eq!(error["ids_text"], serde_json::json!([TINY]));
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
            .immune()
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
    let day = &made["result"]["statements"][0]["at"].as_str().unwrap()[..10];
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
            c.reader == "immune"
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
