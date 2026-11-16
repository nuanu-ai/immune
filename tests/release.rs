//! Promises of the installer package's tooling (`release`, `packaging/`, `docs/release.md`),
//! kept without building or signing anything: the package is for Apple Silicon and the macOS
//! the app names, places its app where it was asked to and runs no script, a signed release
//! refuses before building when a name it signs with is missing, and no signing identity of a
//! real team is written into the repository.

mod common;

use std::path::Path;
use std::process::Command;

const ROOT: &str = env!("CARGO_MANIFEST_DIR");

fn read(rel: &str) -> String {
    std::fs::read_to_string(Path::new(ROOT).join(rel)).unwrap()
}

fn plist_json(rel: &str) -> serde_json::Value {
    let out = Command::new("/usr/bin/plutil")
        .args(["-convert", "json", "-o", "-"])
        .arg(Path::new(ROOT).join(rel))
        .output()
        .unwrap();
    assert!(out.status.success(), "{rel}");
    serde_json::from_slice(&out.stdout).unwrap()
}

const NAMES: [&str; 3] = [
    "IMMUNE_SIGN_APP",
    "IMMUNE_SIGN_INSTALLER",
    "IMMUNE_NOTARY_PROFILE",
];

/// A copy of what `release` reads before it builds, with invented tools that leave a mark
/// in `built` when anything asks them to build.
struct Tree(common::Scratch);

impl Tree {
    fn new(tag: &str, arch: &str) -> Tree {
        let t = Tree(common::Scratch::new(tag));
        for rel in [
            "release",
            "build",
            "app/build",
            "app/Info.plist",
            "scripts/prerequisites.sh",
            "scripts/rust-path.sh",
            "scripts/cargo-built.sh",
        ] {
            let to = t.0.0.join(rel);
            std::fs::create_dir_all(to.parent().unwrap()).unwrap();
            std::fs::copy(Path::new(ROOT).join(rel), to).unwrap();
        }
        let marks = t.0.0.join("built");
        let mark = format!("echo \"$0 $*\" >> '{}'", marks.display());
        t.tool(
            "bin/uname",
            &format!("case \"$1\" in -s) echo Darwin ;; -m) echo {arch} ;; esac"),
        );
        t.tool("bin/sw_vers", "echo 15.6");
        t.tool(
            "bin/xcode-select",
            &format!("echo '{}'", t.0.0.join("dev").display()),
        );
        t.tool(
            "dev/usr/bin/swift",
            &format!(
                "case \"$1\" in --version) echo 'Apple Swift version 6.1.2' ;; *) {mark} ;; esac"
            ),
        );
        t.tool(
            "bin/cargo",
            &format!(
                "case \"$1\" in --version) echo 'cargo 1.89.0 (2025-01-01)' ;; *) {mark} ;; esac"
            ),
        );
        t.tool("bin/git", &format!("{mark}; exit 1"));
        t
    }

    fn tool(&self, rel: &str, body: &str) {
        use std::os::unix::fs::PermissionsExt;
        let path = self.0.0.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    fn release(&self, set: &[&str]) -> (Option<i32>, String) {
        let mut command = Command::new("/bin/sh");
        command
            .arg(self.0.0.join("release"))
            .current_dir(&self.0.0)
            .env(
                "PATH",
                format!("{}:/usr/bin:/bin", self.0.0.join("bin").display()),
            )
            .env("RUST_PLACES", "");
        for name in NAMES {
            command.env_remove(name);
        }
        for name in set {
            command.env(name, "an invented value");
        }
        let out = command.output().unwrap();
        assert!(out.stdout.is_empty());
        (
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    }

    fn built_nothing(&self) -> bool {
        !self.0.0.join("built").exists() && !self.0.0.join("target").exists()
    }
}

#[test]
fn a_signed_release_refuses_before_building_when_a_name_it_signs_with_is_missing() {
    let t = Tree::new("release-names", "arm64");
    for missing in NAMES {
        let set: Vec<&str> = NAMES.into_iter().filter(|n| *n != missing).collect();
        let (code, said) = t.release(&set);
        assert_eq!(code, Some(2), "{said}");
        assert!(said.contains(&format!("not set: {missing}.")), "{said}");
        assert!(said.contains("docs/release.md"), "{said}");
        assert!(t.built_nothing(), "{said}");
    }
    let (code, said) = t.release(&[]);
    assert_eq!(code, Some(2), "{said}");
    assert!(
        said.contains("not set: IMMUNE_SIGN_APP IMMUNE_SIGN_INSTALLER IMMUNE_NOTARY_PROFILE."),
        "{said}"
    );
    assert!(t.built_nothing(), "{said}");
}

#[test]
fn a_release_refuses_an_intel_mac_and_an_uncommitted_tree_before_building() {
    let intel = Tree::new("release-intel", "x86_64");
    for args in [&NAMES[..], &[]] {
        let (code, said) = intel.release(args);
        assert_eq!(code, Some(2), "{said}");
        assert!(said.contains("only on Apple Silicon Macs"), "{said}");
        assert!(intel.built_nothing(), "{said}");
    }

    let dirty = Tree::new("release-dirty", "arm64");
    dirty.tool(
        "bin/git",
        "case \"$1\" in rev-parse) echo 0123456789abcdef0123456789abcdef01234567 ;; status) echo ' M src/main.rs' ;; esac",
    );
    let (code, said) = dirty.release(&NAMES);
    assert_eq!(code, Some(2), "{said}");
    assert!(said.contains("changes that are not committed"), "{said}");
    assert!(dirty.built_nothing(), "{said}");
}

#[test]
fn the_app_for_the_package_records_where_the_package_puts_the_core_and_leaves_a_developers_build() {
    let t = Tree::new("release-core-at", "arm64");
    t.tool("bin/ps", "exit 0");
    t.tool("bin/codesign", "exit 0");
    t.tool("built/ImmuneApp", "exit 99");
    t.tool(
        "bin/swift",
        &format!(
            "case \"$*\" in *--show-bin-path*) echo '{}' ;; esac",
            t.0.0.join("built").display()
        ),
    );
    let own = t.0.0.join("target/app/Immune.app");
    std::fs::create_dir_all(&own).unwrap();
    std::fs::write(own.join("keep"), "a developer's build").unwrap();
    // A place that is not on the Mac that builds.
    let at = "/nonexistent/immune-package-test/immune";
    let run = |args: &[&str]| {
        Command::new("/bin/sh")
            .arg(t.0.0.join("app/build"))
            .args(args)
            .current_dir(&t.0.0)
            .env(
                "PATH",
                format!("{}:/usr/bin:/bin", t.0.0.join("bin").display()),
            )
            .output()
            .unwrap()
    };
    let out = run(&["--core-at", at]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let bundle = String::from_utf8(out.stdout).unwrap();
    assert_eq!(
        Path::new(bundle.trim()),
        t.0.0.join("target/app/package/Immune.app")
    );
    let recorded = Command::new("/usr/bin/plutil")
        .args(["-extract", "ImmuneExecutablePath", "raw", "-o", "-"])
        .arg(Path::new(bundle.trim()).join("Contents/Info.plist"))
        .output()
        .unwrap();
    assert_eq!(String::from_utf8(recorded.stdout).unwrap().trim(), at);
    assert_eq!(
        std::fs::read_to_string(own.join("keep")).unwrap(),
        "a developer's build"
    );
    for args in [
        &["--core-at", "relative/immune"][..],
        &["--core-at"],
        &["--core-at", at, "more"],
        &["--debug", "--core-at", at],
    ] {
        assert_eq!(run(args).status.code(), Some(2), "{args:?}");
    }
}

#[test]
fn the_package_is_for_apple_silicon_and_the_macos_the_app_names_and_runs_no_script() {
    let distribution = read("packaging/distribution.xml");
    // Installer evaluates a distribution that does not name arm64 under Rosetta, and offers
    // to install Rosetta to do it; x86_64 named beside it would let an Intel Mac install.
    assert!(distribution.contains(r#"hostArchitectures="arm64""#));
    assert!(!distribution.contains("x86_64") && !distribution.contains("i386"));
    let minimum = plist_json("app/Info.plist")["LSMinimumSystemVersion"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(
        distribution.contains(&format!(r#"<os-version min="{minimum}"/>"#)),
        "the package must ask for macOS {minimum}, as app/Info.plist does"
    );
    assert_eq!(distribution.matches("<os-version").count(), 1);
    // No JavaScript in the distribution and no script in the package.
    assert!(!distribution.contains("<script") && !distribution.contains("system.run"));
    assert!(distribution.contains(r#"require-scripts="false""#));

    let component = plist_json("packaging/component.plist");
    let bundles = component.as_array().unwrap();
    assert_eq!(bundles.len(), 1);
    let app = &bundles[0];
    let name = plist_json("app/Info.plist")["CFBundleName"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(
        app["RootRelativeBundlePath"],
        format!("Applications/{name}.app").as_str()
    );
    // A developer's own build has the same bundle identifier: a relocatable bundle would
    // be installed over that build, wherever it is, in place of /Applications.
    assert_eq!(app["BundleIsRelocatable"], false);
    assert_eq!(app["BundleOverwriteAction"], "upgrade");
    assert!(
        app.as_object()
            .unwrap()
            .keys()
            .all(|key| !key.contains("Script"))
    );

    let release = read("release");
    assert!(!release.contains("--scripts"));
    assert!(release.contains("--component-plist packaging/component.plist"));
    assert!(release.contains("--distribution packaging/distribution.xml"));
    assert!(release.contains("core_at=/usr/local/bin/immune"));
    assert!(!Path::new(ROOT).join("packaging/scripts").exists());
}

#[test]
fn no_signing_identity_or_team_id_of_a_real_team_is_written_into_the_release_files() {
    let mut files = vec!["release".to_string(), "docs/release.md".to_string()];
    let mut folders = vec![Path::new(ROOT).join("packaging")];
    while let Some(folder) = folders.pop() {
        for entry in std::fs::read_dir(folder).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                folders.push(path);
            } else {
                let rel = path.strip_prefix(ROOT).unwrap();
                files.push(rel.to_str().unwrap().to_string());
            }
        }
    }
    for rel in files {
        let text = read(&rel);
        // A team id is ten capitals and digits, written in parentheses after the team's name.
        let bytes = text.as_bytes();
        for (i, _) in text.match_indices('(') {
            let id = bytes.get(i + 1..i + 11);
            let looks_like_team = id.is_some_and(|id| {
                id.iter()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
            }) && bytes.get(i + 11) == Some(&b')');
            assert!(!looks_like_team, "{rel} holds a team id at byte {i}");
        }
        // An identity's name stays a placeholder: what follows the colon is never a name.
        for kind in ["Developer ID Application:", "Developer ID Installer:"] {
            for (i, _) in text.match_indices(kind) {
                let after = text[i + kind.len()..].trim_start_matches(' ');
                assert!(
                    !after.starts_with(|c: char| c.is_alphanumeric()),
                    "{rel} names a real identity at byte {i}"
                );
            }
        }
    }
}
