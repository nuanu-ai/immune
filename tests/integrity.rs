//! Promises of the integrity reader: content of an installed thing that changed while its
//! version stayed is a `changed` event of its seal, signer or digest, and nothing else is.
//! Every test runs the real binary on an invented estate under a temporary folder: tiny
//! application bundles whose executable is a copy of `/usr/bin/true`, signed ad hoc with the
//! system's `codesign` at test time, a Homebrew keg and a global npm package. The system root
//! and the home folder are temporary, so nothing real is read.

use rusqlite::Connection;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const BUNDLE: &str = "component:machine:mac/macos-app/org.example.tiny";
const KEG: &str = "file:machine:mac//opt/homebrew/Cellar/tool/1.0";
const PACKAGE: &str = "component:machine:mac/npm/tool";

/// The estate's folder, and the store when it is kept somewhere else than in it.
struct Estate(PathBuf, Option<PathBuf>);

impl Estate {
    fn new(tag: &str) -> Estate {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "immune-integrity-{tag}-{}-{nanos}",
            std::process::id()
        ));
        for dir in ["home", "system", "empty"] {
            std::fs::create_dir_all(path.join(dir)).unwrap();
        }
        std::fs::write(path.join("brew.json"), "{\"formulae\": [], \"casks\": []}").unwrap();
        Estate(path, None)
    }

    fn system(&self) -> PathBuf {
        self.0.join("system")
    }

    fn store(&self) -> PathBuf {
        self.1.clone().unwrap_or_else(|| self.0.join("store.db"))
    }

    fn app(&self) -> PathBuf {
        self.system().join("Applications/Tiny.app")
    }

    fn keg(&self) -> PathBuf {
        self.system().join("opt/homebrew/Cellar/tool/1.0")
    }

    fn package(&self) -> PathBuf {
        self.system().join("opt/homebrew/lib/node_modules/tool")
    }

    /// `immune run` on this estate alone, with PATH as given, returning the report line.
    fn run_with_path(&self, path: &str) -> String {
        let empty = self.0.join("empty");
        let out = Command::new(env!("CARGO_BIN_EXE_immune"))
            .env("HOME", self.0.join("home"))
            .env("PATH", path)
            .current_dir(&self.0)
            .args(["run", "--machine-name", "mac", "--store"])
            .arg(self.store())
            .arg("--system-root")
            .arg(self.system())
            .arg("--brew-input")
            .arg(self.0.join("brew.json"))
            .args(["--tailscale", "none", "--threats-input", "none"])
            .args(["--osv-crates-input", "none", "--osv-npm-input", "none"])
            .arg("--checkouts-root")
            .arg(&empty)
            .arg("--sessions-root")
            .arg(&empty)
            .arg("--servers-input")
            .arg(&empty)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap()
    }

    fn run(&self) -> String {
        self.run_with_path("/usr/bin:/bin")
    }

    fn db(&self) -> Connection {
        Connection::open(self.store()).unwrap()
    }

    /// The integrity reader's events of the last run, as entry, subject and predicate.
    fn events(&self) -> Vec<(String, String, String)> {
        let db = self.db();
        let mut stmt = db
            .prepare(
                "SELECT entry, subject, predicate FROM journal
                 WHERE reader = 'integrity' AND entry IN ('added', 'changed', 'removed')
                   AND run_id = (SELECT run_id FROM journal WHERE entry = 'run_finished'
                                 ORDER BY seq DESC LIMIT 1)
                 ORDER BY seq",
            )
            .unwrap();
        stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap()
    }

    /// The live objects of one subject and predicate.
    fn live(&self, subject: &str, predicate: &str) -> Vec<String> {
        let db = self.db();
        let mut stmt = db
            .prepare(
                "SELECT object FROM assertion WHERE layer = 'live' AND subject = ?1
                   AND predicate = ?2 ORDER BY object",
            )
            .unwrap();
        stmt.query_map([subject, predicate], |r| r.get(0))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap()
    }

    fn home(&self) -> PathBuf {
        self.0.join("home")
    }

    /// `immune <args> --json --store <this store>`, as the contract's message.
    fn contract(&self, args: &[&str]) -> serde_json::Value {
        let out = Command::new(env!("CARGO_BIN_EXE_immune"))
            .args(args)
            .args(["--json", "--store"])
            .arg(self.store())
            .output()
            .unwrap();
        assert!(out.status.success());
        serde_json::from_slice(&out.stdout).unwrap()
    }

    /// The open findings, as rule, where and what the seal or the signer became.
    fn findings(&self) -> Vec<(String, String, String)> {
        let s = |v: &serde_json::Value| v.as_str().unwrap_or_default().to_string();
        self.contract(&["findings"])["findings"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|f| f["finding"]["state"] == "open")
            .map(|f| {
                let one = self.contract(&["finding", f["finding"]["id"].as_str().unwrap()]);
                (
                    s(&f["finding"]["rule"]),
                    s(&f["where_text"]),
                    s(&one["evidence"]["changed_in_place"]["became_text"]),
                )
            })
            .collect()
    }

    /// The `integrity` section of `immune status --json`.
    fn status(&self) -> serde_json::Value {
        let out = Command::new(env!("CARGO_BIN_EXE_immune"))
            .args(["status", "--json", "--store"])
            .arg(self.store())
            .output()
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        v["result"]["integrity"].clone()
    }
}

impl Drop for Estate {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn plist(version: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict>\n<key>CFBundleIdentifier</key><string>org.example.tiny</string>\n<key>CFBundleExecutable</key><string>Tiny</string>\n<key>CFBundlePackageType</key><string>APPL</string>\n<key>CFBundleShortVersionString</key><string>{version}</string>\n<key>CFBundleVersion</key><string>7</string>\n</dict></plist>\n"
    )
}

/// A tiny bundle at `app` whose code is a copy of `/usr/bin/true`, signed ad hoc.
fn bundle(app: &Path, version: &str) {
    let contents = app.join("Contents");
    std::fs::create_dir_all(contents.join("MacOS")).unwrap();
    std::fs::create_dir_all(contents.join("Resources/app")).unwrap();
    std::fs::write(contents.join("Info.plist"), plist(version)).unwrap();
    std::fs::copy("/usr/bin/true", contents.join("MacOS/Tiny")).unwrap();
    std::fs::write(contents.join("Resources/app/main.js"), "start();\n").unwrap();
    sign(app);
}

fn sign(app: &Path) {
    let out = Command::new("/usr/bin/codesign")
        .args(["--force", "--sign", "-"])
        .arg(app)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn put(path: &Path, text: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

fn append(path: &Path, text: &str) {
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new().append(true).open(path).unwrap();
    f.write_all(text.as_bytes()).unwrap();
}

fn package(dir: &Path, version: &str) {
    put(
        &dir.join("package.json"),
        &format!("{{\"name\": \"tool\", \"version\": \"{version}\"}}\n"),
    );
    put(&dir.join("lib/cli.js"), "run();\n");
}

/// The events of one subject, as entry and predicate.
fn of(events: &[(String, String, String)], subject: &str) -> Vec<(String, String)> {
    events
        .iter()
        .filter(|(_, s, _)| s == subject)
        .map(|(e, _, p)| (e.clone(), p.clone()))
        .collect()
}

fn pair(entry: &str, predicate: &str) -> (String, String) {
    (entry.to_string(), predicate.to_string())
}

#[test]
fn code_appended_inside_a_signed_bundle_at_the_same_version_is_one_changed_event_on_its_seal() {
    // The incident's step (a): code appended to a JavaScript file inside an application's
    // bundle, nothing else touched.
    let e = Estate::new("append");
    bundle(&e.app(), "1.0");
    e.run();
    assert_eq!(e.live(BUNDLE, "has_seal"), ["verifies"]);
    append(
        &e.app().join("Contents/Resources/app/main.js"),
        "steal();\n",
    );
    let line = e.run();
    let events = of(&e.events(), BUNDLE);
    let seal: Vec<_> = events.iter().filter(|(_, p)| p == "has_seal").collect();
    assert_eq!(seal, [&pair("changed", "has_seal")]);
    assert!(
        !events
            .iter()
            .any(|(_, p)| p == "has_version" || p == "signed_by")
    );
    assert_eq!(
        e.live(BUNDLE, "has_seal"),
        ["does not verify: a sealed resource is missing or invalid"]
    );
    assert_eq!(e.status()["changed_while_version_stayed"], 1);
    assert!(
        line.contains("1 changed while the version stayed, since the last reading; 1 bundle does not verify, 0 of them since the first reading."),
        "{line}"
    );
    // It is a finding: where is the bundle's path, and what it became is the seal's words.
    assert_eq!(
        e.findings(),
        [(
            "integrity.app-seal".to_string(),
            "/Applications/Tiny.app".to_string(),
            "does not verify: a sealed resource is missing or invalid".to_string()
        )]
    );
}

#[test]
fn a_file_added_inside_a_signed_bundle_breaks_its_seal() {
    let e = Estate::new("added");
    bundle(&e.app(), "1.0");
    e.run();
    put(
        &e.app().join("Contents/Resources/app/extra.js"),
        "steal();\n",
    );
    e.run();
    assert!(of(&e.events(), BUNDLE).contains(&pair("changed", "has_seal")));
    assert_eq!(e.status()["changed_while_version_stayed"], 1);
}

#[test]
fn a_new_version_with_a_valid_seal_is_an_update_not_a_change_in_place() {
    let e = Estate::new("update");
    bundle(&e.app(), "1.0");
    e.run();
    std::fs::write(e.app().join("Contents/Info.plist"), plist("2.0")).unwrap();
    append(&e.app().join("Contents/Resources/app/main.js"), "more();\n");
    sign(&e.app());
    let line = e.run();
    let events = of(&e.events(), BUNDLE);
    assert!(
        events.contains(&pair("changed", "has_version")),
        "{events:?}"
    );
    assert!(!events.iter().any(|(_, p)| p == "has_seal"), "{events:?}");
    assert_eq!(e.live(BUNDLE, "has_version"), ["2.0 (7)"]);
    assert_eq!(e.status()["changed_while_version_stayed"], 0);
    assert!(
        line.contains("0 changed while the version stayed"),
        "{line}"
    );
}

#[test]
fn a_bundle_signed_again_after_tampering_shows_as_another_signer_at_the_same_version() {
    // An attacker who also signs the bundle again passes verification; an ad hoc signature
    // names its code directory, so the signer is another one while the version stays.
    let e = Estate::new("resign");
    bundle(&e.app(), "1.0");
    e.run();
    let before = e.live(BUNDLE, "signed_by");
    append(
        &e.app().join("Contents/Resources/app/main.js"),
        "steal();\n",
    );
    sign(&e.app());
    e.run();
    let events = of(&e.events(), BUNDLE);
    assert!(events.contains(&pair("changed", "signed_by")), "{events:?}");
    assert!(
        !events
            .iter()
            .any(|(_, p)| p == "has_seal" || p == "has_version")
    );
    assert_ne!(e.live(BUNDLE, "signed_by"), before);
    assert_eq!(e.status()["changed_while_version_stayed"], 1);
    let found = e.findings();
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0].0, "integrity.app-signer");
    assert_eq!(found[0].2, e.live(BUNDLE, "signed_by")[0]);
}

#[test]
fn a_keg_or_package_changed_in_place_is_one_changed_event_and_a_new_version_is_not() {
    // The incident's step (c): code appended to a global package's file. A keg's folder is
    // its version, so a new version is a new folder; a package says its version itself.
    let e = Estate::new("keg");
    put(&e.keg().join("bin/tool"), "#!/bin/sh\n");
    package(&e.package(), "1.0.0");
    e.run();
    append(&e.keg().join("bin/tool"), "steal\n");
    append(&e.package().join("lib/cli.js"), "steal();\n");
    e.run();
    let events = e.events();
    assert_eq!(of(&events, KEG), [pair("changed", "has_digest")]);
    assert_eq!(of(&events, PACKAGE), [pair("changed", "has_digest")]);
    assert_eq!(e.status()["changed_while_version_stayed"], 2);
    let mut found = e.findings();
    found.sort();
    assert_eq!(
        found,
        [
            (
                "integrity.package-files".to_string(),
                "/opt/homebrew/Cellar/tool/1.0".to_string(),
                String::new()
            ),
            (
                "integrity.package-files".to_string(),
                "/opt/homebrew/lib/node_modules/tool".to_string(),
                String::new()
            ),
        ]
    );

    std::fs::remove_dir_all(e.keg()).unwrap();
    put(
        &e.keg().with_file_name("1.1").join("bin/tool"),
        "#!/bin/sh\n",
    );
    package(&e.package(), "1.1.0");
    e.run();
    let events = e.events();
    assert_eq!(
        of(&events, KEG),
        [pair("removed", "has_digest"), pair("removed", "located_on")]
    );
    assert!(of(&events, PACKAGE).contains(&pair("changed", "has_version")));
    assert!(of(&events, &KEG.replace("1.0", "1.1")).contains(&pair("added", "has_digest")));
    assert_eq!(e.status()["changed_while_version_stayed"], 0);
}

#[test]
fn the_first_reading_is_the_baseline_and_a_second_on_unchanged_inputs_reports_no_changes() {
    let e = Estate::new("baseline");
    bundle(&e.app(), "1.0");
    // A bundle that does not verify at the first reading is part of the baseline.
    let unsigned = e.system().join("Applications/Suite/Plain.app/Contents");
    // Its Info.plist gives no short version, only the build.
    put(
        &unsigned.join("Info.plist"),
        &plist("1.0").replace("tiny", "plain").replace(
            "<key>CFBundleShortVersionString</key><string>1.0</string>\n",
            "",
        ),
    );
    put(&e.keg().join("bin/tool"), "#!/bin/sh\n");
    package(&e.package(), "1.0.0");
    // A link to a bundle is not followed, npm's `.bin` folder is not a package, and a scoped
    // package is one.
    std::os::unix::fs::symlink(e.app(), e.system().join("Applications/Link.app")).unwrap();
    std::fs::create_dir_all(e.system().join("Applications/Suite/Read Me")).unwrap();
    put(&e.system().join("opt/homebrew/Cellar/.DS_Store"), "x");
    put(&e.system().join("opt/homebrew/Cellar/tool/.DS_Store"), "x");
    let modules = e.package().parent().unwrap().to_path_buf();
    let plain = "component:machine:mac/macos-app/org.example.plain";
    put(&modules.join(".bin/tool"), "#!/bin/sh\n");
    package(&modules.join("@scope/kit"), "2.0.0");
    let first = e.run();
    assert!(
        first.contains("Installed software: 2 application bundles, 1 Homebrew keg, 2 global npm packages, first reading, kept as the baseline; 1 bundle does not verify, 1 of them since the first reading."),
        "{first}"
    );
    assert_eq!(
        e.live("component:machine:mac/npm/@scope/kit", "has_version"),
        ["2.0.0"]
    );
    assert_eq!(e.live(plain, "has_version"), ["7"]);
    // Each fact points at its own line of the raw copy.
    let source: String = e
        .db()
        .query_row(
            "SELECT source_ref FROM assertion WHERE layer = 'live' AND subject = ?1
               AND predicate = 'has_seal'",
            [BUNDLE],
            |r| r.get(0),
        )
        .unwrap();
    let (file, line) = source.rsplit_once(':').unwrap();
    let raw = std::fs::read_to_string(e.0.join(file)).unwrap();
    let line = raw.lines().nth(line.parse::<usize>().unwrap() - 1).unwrap();
    assert!(
        line.contains(BUNDLE) && line.contains("has_seal=verifies"),
        "{line}"
    );
    let second = e.run();
    assert!(
        second.contains("Since last run: no changes.")
            && second.contains("0 changed while the version stayed, since the last reading"),
        "{second}"
    );
    assert!(e.events().is_empty());
    assert!(e.findings().is_empty());
    // The seals were not verified again: nothing moved, so each verdict was carried forward.
    let s = e.status();
    assert_eq!(
        (&s["seals_verified_this_run"], &s["seals_carried_forward"]),
        (&serde_json::json!(0), &serde_json::json!(2))
    );
    let note = s["readings"][0]["reason_text"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(note.contains("carried forward for 2"), "{note}");
    // A digest that moves without a change of version has the seal verified again.
    append(
        &e.app().join("Contents/Resources/app/main.js"),
        "steal();\n",
    );
    e.run();
    assert_eq!(e.status()["seals_verified_this_run"], 1);
}

#[test]
fn a_bundle_or_folder_that_cannot_be_read_retracts_nothing() {
    use std::os::unix::fs::PermissionsExt;
    let e = Estate::new("unreadable");
    bundle(&e.app(), "1.0");
    put(&e.keg().join("lib/inner/x.rb"), "x\n");
    package(&e.package(), "1.0.0");
    e.run();
    let shut = [
        e.app().join("Contents/Resources"),
        e.keg().join("lib/inner"),
        e.package().parent().unwrap().to_path_buf(),
    ];
    for dir in &shut {
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o000)).unwrap();
    }
    let line = e.run();
    for dir in &shut {
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    assert!(
        line.contains("not read in full: application bundles in /Applications and ~/Applications (partial), Homebrew kegs (partial), global npm packages (nothing read)"),
        "{line}"
    );
    assert!(
        !e.events().iter().any(|(entry, _, _)| entry == "removed"),
        "{:?}",
        e.events()
    );
    assert_eq!(e.live(BUNDLE, "has_seal"), ["verifies"]);
    assert_eq!(e.live(KEG, "located_on"), ["machine:mac"]);
    let readings = &e.status()["readings"];
    assert_eq!(readings[0]["completeness"], "partial");
    assert_eq!(readings[1]["completeness"], "partial");
    // The only place of global packages could not be listed: nothing was read there.
    assert_eq!(readings[2]["completeness"], "none");
    let reason = readings[2]["reason_text"].as_str().unwrap();
    assert!(
        reason.starts_with("could not be read: /opt/homebrew/lib/node_modules"),
        "{reason}"
    );
    assert!(!reason.contains("none of these places"), "{reason}");
    assert_eq!(e.live(PACKAGE, "has_version"), ["1.0.0"]);
}

#[test]
fn a_mac_without_any_of_these_places_is_read_in_full_and_is_not_a_failure() {
    // A place that is not there is not applicable; the reader then had nothing to read and
    // is not counted among the readers that had input.
    let e = Estate::new("empty");
    let readers = |line: &str| line.split(' ').next().unwrap().parse::<u32>().unwrap();
    let empty = e.run();
    let readings = e.status()["readings"].clone();
    for r in readings.as_array().unwrap() {
        assert_eq!(r["completeness"], "full");
        let note = r["reason_text"].as_str().unwrap();
        assert!(
            note.starts_with("none of these places is on this machine"),
            "{note}"
        );
    }
    assert!(!empty.contains("not read in full"), "{empty}");
    bundle(&e.app(), "1.0");
    let one = e.run();
    assert_eq!(readers(&one), readers(&empty) + 1, "{empty}\n{one}");
}

#[test]
fn two_things_under_one_name_keep_the_first_and_the_reading_says_it_is_not_full() {
    // Two copies of one application, or one package under both prefixes: a component is
    // named by its name, so the later one in order of path is not recorded, and nothing of
    // its kind is retracted while that is so.
    let e = Estate::new("shared");
    bundle(&e.app(), "1.0");
    bundle(&e.system().join("Applications/Suite/Copy.app"), "1.0");
    package(&e.package(), "1.0.0");
    let local = e.system().join("usr/local/lib/node_modules/tool");
    package(&local, "1.0.0");
    let line = e.run();
    assert_eq!(
        e.live(BUNDLE, "installed_at"),
        ["/Applications/Suite/Copy.app"]
    );
    assert_eq!(
        e.live(PACKAGE, "installed_at"),
        ["/opt/homebrew/lib/node_modules/tool"]
    );
    let readings = e.status()["readings"].clone();
    for i in [0, 2] {
        assert_eq!(readings[i]["completeness"], "partial");
        let reason = readings[i]["reason_text"].as_str().unwrap();
        assert!(reason.contains("another one has the same name"), "{reason}");
    }
    let cause: String = e
        .db()
        .query_row(
            "SELECT cause FROM coverage WHERE reader = 'integrity' AND kind = ?1",
            ["global npm packages"],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(cause, "not_given");
    assert!(
        line.contains("not read in full: application bundles in /Applications and ~/Applications (partial), global npm packages (partial)"),
        "{line}"
    );
}

#[test]
fn what_macos_or_python_write_by_themselves_is_not_a_change_in_place() {
    // macOS adds attributes to a bundle's folder; Python writes its cache into a keg; a file
    // rewritten with the same content has its seal verified again and still verifies.
    let e = Estate::new("noise");
    bundle(&e.app(), "1.0");
    put(&e.keg().join("lib/m.py"), "x = 1\n");
    e.run();
    let out = Command::new("/usr/bin/xattr")
        .args(["-w", "org.example.seen", "1"])
        .arg(e.app())
        .output()
        .unwrap();
    assert!(out.status.success());
    put(&e.keg().join("lib/__pycache__/m.cpython-312.pyc"), "cache");
    e.run();
    assert!(e.events().is_empty(), "{:?}", e.events());
    assert_eq!(e.status()["seals_verified_this_run"], 0);
    put(
        &e.app().join("Contents/Resources/app/main.js"),
        "start();\n",
    );
    e.run();
    assert_eq!(of(&e.events(), BUNDLE), [pair("changed", "has_digest")]);
    let s = e.status();
    assert_eq!(s["seals_verified_this_run"], 1);
    assert_eq!(s["changed_while_version_stayed"], 0);
}

#[test]
fn a_file_rewritten_and_given_back_its_old_modification_time_still_moves_the_digest() {
    let e = Estate::new("mtime");
    let file = e.keg().join("bin/tool");
    put(&file, "aaaa");
    e.run();
    let modified = std::fs::metadata(&file).unwrap().modified().unwrap();
    std::fs::write(&file, "bbbb").unwrap();
    std::fs::File::options()
        .write(true)
        .open(&file)
        .unwrap()
        .set_modified(modified)
        .unwrap();
    e.run();
    assert_eq!(of(&e.events(), KEG), [pair("changed", "has_digest")]);
}

#[test]
fn content_never_appears_in_the_store_or_the_raw_copy() {
    let e = Estate::new("content");
    let marker = "SECRET-MARKER-41f3";
    bundle(&e.app(), "1.0");
    append(&e.app().join("Contents/Resources/app/main.js"), marker);
    put(&e.keg().join("bin/tool"), marker);
    package(&e.package(), "1.0.0");
    append(&e.package().join("lib/cli.js"), marker);
    e.run();
    e.run();
    let mut files = vec![e.store()];
    let mut dirs = vec![e.0.join("raw")];
    while let Some(dir) = dirs.pop() {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                dirs.push(path);
            } else {
                files.push(path);
            }
        }
    }
    assert!(files.len() > 1, "a raw copy is kept");
    for file in files {
        let bytes = std::fs::read(&file).unwrap();
        assert!(
            !bytes.windows(marker.len()).any(|w| w == marker.as_bytes()),
            "{}",
            file.display()
        );
    }
}

#[test]
fn the_reader_never_runs_a_tool_found_through_path() {
    // What a tool prints becomes facts. Tools named like the system's own, first on PATH,
    // would be run if the reader looked them up.
    let e = Estate::new("path");
    bundle(&e.app(), "1.0");
    let bin = e.0.join("bin");
    let ran = e.0.join("ran");
    for tool in ["plutil", "codesign"] {
        let script = bin.join(tool);
        put(
            &script,
            &format!(
                "#!/bin/sh\necho {tool} >> '{}'\necho 6.6.6\n",
                ran.display()
            ),
        );
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    e.run_with_path(&format!("{}:/usr/bin:/bin", bin.display()));
    assert!(!ran.exists(), "{}", std::fs::read_to_string(&ran).unwrap());
    assert_eq!(e.live(BUNDLE, "has_version"), ["1.0 (7)"]);
}

#[test]
fn a_store_kept_before_this_reader_existed_takes_its_first_reading_as_the_baseline() {
    // The owner's store holds runs made before this reader; its first reading there must not
    // count every application as added since the last run.
    let e = Estate::new("older");
    e.run();
    let db = e.db();
    db.execute_batch(
        "DELETE FROM coverage_lack WHERE coverage IN
             (SELECT id FROM coverage WHERE reader = 'integrity');
         DELETE FROM coverage WHERE reader = 'integrity';",
    )
    .unwrap();
    drop(db);
    bundle(&e.app(), "1.0");
    let line = e.run();
    assert!(line.contains("Since last run: no changes."), "{line}");
    assert!(
        line.contains("first reading, kept as the baseline"),
        "{line}"
    );
    assert!(e.findings().is_empty());
}

/// The code an application keeps in its folder under Application Support.
fn module(e: &Estate, folder: &str) -> PathBuf {
    e.home()
        .join("Library/Application Support")
        .join(folder)
        .join("1.0/modules/index.js")
}

#[test]
fn code_an_application_keeps_outside_its_bundle_changed_while_its_version_stayed_is_found() {
    // The incident's step (b): code appended to a module an application keeps in its own
    // folder under Application Support. The folder is found by the application's name,
    // ignoring case.
    let e = Estate::new("outside");
    bundle(&e.app(), "1.0");
    let js = module(&e, "TINY");
    put(&js, "start();\n");
    put(&js.with_file_name("notes.txt"), "a\n");
    let modules = js.parent().unwrap().to_path_buf();
    let noise = [
        "Code Cache/js/x.js",
        "Service Worker/x.js",
        "IndexedDB/x.js",
        "Local Storage/x.js",
        "Session Storage/x.js",
        "blob_storage/x.js",
        "Crashpad/x.js",
        "logs/x.js",
    ];
    for n in noise {
        put(&modules.join(n), "a\n");
    }
    // A file named like the application is not its folder.
    put(
        &e.home()
            .join("Library/Application Support/org.example.tiny"),
        "x",
    );
    // A folder no application read here is named after is never opened.
    put(&module(&e, "Unrelated"), "start();\n");
    let first = e.run();
    let folder = "file:machine:mac/Library/Application Support/TINY";
    assert_eq!(e.live(folder, "has_version"), ["1.0 (7)"]);
    assert!(
        e.live(
            "file:machine:mac/Library/Application Support/Unrelated",
            "has_digest"
        )
        .is_empty()
    );
    let note = e.status()["readings"][3]["reason_text"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(
        note.starts_with("1 folders matched an application, 1 code files compared"),
        "{note}"
    );
    assert!(first.contains("first reading"), "{first}");
    assert_eq!(e.status()["readings"][3]["completeness"], "full");
    // What is not code, and caches, web storage, crash reports and logs, change on their own:
    // nothing.
    append(&js.with_file_name("notes.txt"), "b\n");
    for n in noise {
        append(&modules.join(n), "b\n");
    }
    append(&module(&e, "Unrelated"), "steal();\n");
    e.run();
    assert!(e.events().is_empty(), "{:?}", e.events());
    // A program anyone may run is code, whatever its name.
    let helper = modules.join("helper");
    put(&helper, "#!/bin/sh\n");
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o755)).unwrap();
    e.run();
    assert_eq!(of(&e.events(), folder), [pair("changed", "has_digest")]);
    // The module changed while the application stayed at its version.
    append(&js, "steal();\n");
    e.run();
    assert_eq!(of(&e.events(), folder), [pair("changed", "has_digest")]);
    assert_eq!(
        e.findings(),
        [(
            "integrity.app-code-outside".to_string(),
            "~/Library/Application Support/TINY".to_string(),
            String::new()
        )]
    );
    // An update of the application with its code there is not that.
    append(&js, "more();\n");
    std::fs::write(e.app().join("Contents/Info.plist"), plist("2.0")).unwrap();
    sign(&e.app());
    e.run();
    assert_eq!(e.status()["changed_while_version_stayed"], 0);
}

#[test]
fn the_folder_that_holds_the_store_is_not_an_applications_code_while_another_named_alike_is() {
    // Tiny stands for this program: its store is in a folder named by its identifier, beside
    // pages and scripts the program rewrites. Other is any application with a folder named
    // the same way.
    let mut e = Estate::new("own");
    bundle(&e.app(), "1.0");
    let other = e.system().join("Applications/Other.app");
    bundle(&other, "1.0");
    let info = other.join("Contents/Info.plist");
    let text = std::fs::read_to_string(&info).unwrap();
    std::fs::write(&info, text.replace("org.example.tiny", "org.example.other")).unwrap();
    sign(&other);
    let support = e.home().join("Library/Application Support");
    let own = support.join("org.example.tiny");
    std::fs::create_dir_all(&own).unwrap();
    e.1 = Some(own.join("store.db"));
    let live = own.join("pages/live.js");
    put(&live, "window.immuneLive = {};\n");
    put(&own.join("sweep.sh"), "#!/bin/sh\n");
    let js = module(&e, "org.example.other");
    put(&js, "start();\n");
    e.run();
    // The code files there change between the two runs, as they do while the program works.
    append(&live, "window.immuneLive = {};\n");
    append(&own.join("sweep.sh"), "exit 0\n");
    append(&js, "steal();\n");
    e.run();
    let own_folder = "file:machine:mac/Library/Application Support/org.example.tiny";
    let other_folder = "file:machine:mac/Library/Application Support/org.example.other";
    assert!(of(&e.events(), own_folder).is_empty(), "{:?}", e.events());
    assert!(e.live(own_folder, "has_digest").is_empty());
    assert!(e.live(own_folder, "located_on").is_empty());
    assert_eq!(
        of(&e.events(), other_folder),
        [pair("changed", "has_digest")]
    );
    assert_eq!(
        e.findings(),
        [(
            "integrity.app-code-outside".to_string(),
            "~/Library/Application Support/org.example.other".to_string(),
            String::new()
        )]
    );
}

#[test]
fn a_folder_named_after_an_application_apple_signed_is_never_looked_into() {
    // macOS guards some folders under Application Support with a dialog; all are Apple's. A
    // copy of an application of Apple's is signed by Apple.
    let e = Estate::new("apple");
    let apps = e.system().join("Applications");
    std::fs::create_dir_all(&apps).unwrap();
    let out = Command::new("/bin/cp")
        .arg("-R")
        .arg("/System/Applications/Calculator.app")
        .arg(apps.join("Calculator.app"))
        .output()
        .unwrap();
    assert!(out.status.success());
    put(&module(&e, "Calculator"), "start();\n");
    put(&module(&e, "com.apple.calculator"), "start();\n");
    e.run();
    assert_eq!(
        e.live(
            "component:machine:mac/macos-app/com.apple.calculator",
            "signed_by"
        ),
        ["apple"]
    );
    assert_eq!(e.status()["application_code_folders"], 0);
}

#[test]
fn a_folder_over_a_cap_is_not_recorded_and_the_reading_says_so() {
    let e = Estate::new("caps");
    bundle(&e.app(), "1.0");
    let deep = (0..17).fold(e.home().join("Library/Application Support/Tiny"), |p, i| {
        p.join(format!("d{i}"))
    });
    put(&deep.join("x.js"), "x\n");
    let many = e
        .home()
        .join("Library/Application Support/org.example.tiny");
    std::fs::create_dir_all(&many).unwrap();
    for i in 0..20_001 {
        std::fs::write(many.join(format!("{i}.js")), "").unwrap();
    }
    e.run();
    let r = &e.status()["readings"][3];
    assert_eq!(r["completeness"], "partial");
    let reason = r["reason_text"].as_str().unwrap();
    assert!(
        reason.contains("Tiny (deeper than 16 folders)")
            && reason.contains("org.example.tiny (more than 20000 code files)"),
        "{reason}"
    );
    let cause: String = e
        .db()
        .query_row(
            "SELECT cause FROM coverage WHERE kind = ?1",
            ["code kept by applications not signed by Apple under ~/Library/Application Support"],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(cause, "not_given");
}

#[test]
fn an_application_that_cannot_be_read_takes_nothing_from_its_folder() {
    use std::os::unix::fs::PermissionsExt;
    let e = Estate::new("outside-unreadable");
    bundle(&e.app(), "1.0");
    put(&module(&e, "Tiny"), "start();\n");
    e.run();
    let shut = e.app().join("Contents/Resources");
    std::fs::set_permissions(&shut, std::fs::Permissions::from_mode(0o000)).unwrap();
    e.run();
    std::fs::set_permissions(&shut, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(e.events().is_empty(), "{:?}", e.events());
    assert_eq!(e.status()["readings"][3]["completeness"], "partial");
}

#[test]
fn a_bundle_that_starts_to_verify_at_the_same_version_raises_no_broken_seal() {
    // An unsigned application signed at the same version: its signer is another, which is
    // found; its seal now verifies, which is not a seal broken.
    let e = Estate::new("verifies-again");
    let app = e.app();
    bundle(&app, "1.0");
    let out = Command::new("/usr/bin/codesign")
        .arg("--remove-signature")
        .arg(&app)
        .output()
        .unwrap();
    assert!(out.status.success());
    e.run();
    assert_ne!(e.live(BUNDLE, "has_seal"), ["verifies"]);
    sign(&app);
    e.run();
    assert!(of(&e.events(), BUNDLE).contains(&pair("changed", "has_seal")));
    let rules: Vec<String> = e.findings().into_iter().map(|f| f.0).collect();
    assert_eq!(rules, ["integrity.app-signer"]);
}

#[test]
fn a_place_of_apps_or_a_packages_file_linked_into_documents_is_not_looked_into_and_is_said() {
    // A run the app starts must not make macOS ask the owner for his Documents because
    // ~/Applications, or a package's own file, is a link into it. Documents is shut here, as
    // macOS keeps it: a reader that entered it would say "Permission denied" instead, or
    // lose the package's version without a word.
    use std::os::unix::fs::{PermissionsExt, symlink};
    let e = Estate::new("linked-guarded");
    let docs = e.home().join("Documents");
    std::fs::create_dir_all(docs.join("Apps/Other.app/Contents")).unwrap();
    symlink(docs.join("Apps"), e.home().join("Applications")).unwrap();
    package(&e.package(), "1.0");
    std::fs::rename(e.package().join("package.json"), docs.join("package.json")).unwrap();
    symlink(docs.join("package.json"), e.package().join("package.json")).unwrap();
    std::fs::set_permissions(&docs, std::fs::Permissions::from_mode(0o000)).unwrap();
    e.run();
    std::fs::set_permissions(&docs, std::fs::Permissions::from_mode(0o755)).unwrap();
    let latest = |kind: &str| -> String {
        e.db()
            .query_row(
                "SELECT completeness || '|' || ifnull(cause, 'NULL') || '|' || reason FROM coverage
                 WHERE reader = 'integrity' AND kind = ?1 ORDER BY id DESC LIMIT 1",
                [kind],
                |r| r.get(0),
            )
            .unwrap()
    };
    const INTO: &str = "it leads into ~/Documents, which macOS asks permission for";
    let bundles = latest("application bundles in /Applications and ~/Applications");
    assert!(
        bundles.starts_with(&format!(
            "none|not_given|not looked into: Applications: {INTO}"
        )),
        "{bundles}"
    );
    let npm = latest("global npm packages");
    assert!(
        npm.starts_with(&format!(
            "partial|not_given|not looked into: /opt/homebrew/lib/node_modules/tool/package.json: {INTO}"
        )),
        "{npm}"
    );
    assert_eq!(
        latest("folders macOS asks permission for"),
        "none|not_given|not looked into: ~/Documents"
    );
    // The words say what was not looked into.
    let out = Command::new(env!("CARGO_BIN_EXE_immune"))
        .args(["status", "--json", "--store"])
        .arg(e.store())
        .output()
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let titles: Vec<&str> = v["result"]["not_covered"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|u| u["id"] == "protected-folders")
        .map(|u| u["title"].as_str().unwrap())
        .collect();
    assert_eq!(
        titles,
        ["Installed apps and packages inside Documents are not checked."]
    );
}
