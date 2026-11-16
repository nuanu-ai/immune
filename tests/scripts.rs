//! Promises of the scripts that build and check the program on a colleague's Mac: what they
//! ask of the Mac is said once and asked by both, and the build finds the binary where cargo
//! put it. Builds run only in temporary trees against invented tools.

mod common;

use std::path::{Path, PathBuf};
use std::process::Command;

const ROOT: &str = env!("CARGO_MANIFEST_DIR");

fn read(rel: &str) -> String {
    std::fs::read_to_string(Path::new(ROOT).join(rel)).unwrap()
}

/// A folder of invented tools, removed when the test ends.
struct Tools(PathBuf);

impl Tools {
    fn new(tag: &str) -> Tools {
        let dir = std::env::temp_dir().join(format!("immune-scripts-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("bin")).unwrap();
        Tools(dir.canonicalize().unwrap())
    }

    fn tool(&self, rel: &str, body: &str) {
        use std::os::unix::fs::PermissionsExt;
        let path = self.0.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    /// A Mac with this macOS, this Swift in its Command Line Tools and this cargo.
    fn mac(&self, macos: &str, swift: &str, cargo: &str) {
        self.tool(
            "bin/uname",
            "case \"$1\" in -s) echo Darwin ;; -m) echo arm64 ;; esac",
        );
        self.tool("bin/sw_vers", &format!("echo {macos}"));
        self.tool(
            "bin/xcode-select",
            &format!("echo {}", self.0.join("tools").display()),
        );
        self.tool(
            "tools/usr/bin/swift",
            &format!("echo 'swift-driver version: 1.120.5 Apple Swift version {swift} (swiftlang-6.1.2.1.2 clang-1700.0.13.5)'\necho 'Target: arm64-apple-macosx15.0'"),
        );
        self.tool("bin/cargo", &format!("echo 'cargo {cargo} (2025-01-01)'"));
    }

    fn checkout(&self) {
        for rel in [
            "build",
            "check",
            "app/build",
            "app/Info.plist",
            "scripts/prerequisites.sh",
            "scripts/rust-path.sh",
            "scripts/cargo-built.sh",
        ] {
            let destination = self.0.join(rel);
            std::fs::create_dir_all(destination.parent().unwrap()).unwrap();
            std::fs::copy(Path::new(ROOT).join(rel), destination).unwrap();
        }
    }

    fn run(&self, script: &str, args: &[&str]) -> std::process::Output {
        Command::new("/bin/sh")
            .arg(self.0.join(script))
            .args(args)
            .current_dir(&self.0)
            .env(
                "PATH",
                format!("{}:/usr/bin:/bin", self.0.join("bin").display()),
            )
            .env("RUST_PLACES", "")
            .output()
            .unwrap()
    }

    /// The prerequisites as `./check` and `./build` source them: the exit code and stderr.
    fn prerequisites(&self, part: &str) -> (Option<i32>, String) {
        let out = Command::new("/bin/sh")
            .arg("-c")
            .arg(format!(
                ". ./scripts/prerequisites.sh; {part}_prerequisites"
            ))
            .current_dir(ROOT)
            .env(
                "PATH",
                format!("{}:/usr/bin:/bin", self.0.join("bin").display()),
            )
            .output()
            .unwrap();
        (
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    }
}

impl Drop for Tools {
    fn drop(&mut self) {
        common::remove(&self.0);
    }
}

#[test]
fn app_checks_refuse_old_macos_or_swift_and_say_what_to_install() {
    // macOS 14 has no /usr/bin/jq, which the collector and tests need, and its Command Line
    // Tools carry no Swift 6, which the app's package asks for.
    let t = Tools::new("prerequisites");
    t.mac("14.6.1", "6.0.3", "1.89.0");
    let (code, said) = t.prerequisites("swift");
    assert_eq!(code, Some(2), "{said}");
    assert!(
        said.contains(
            "only on Apple Silicon Macs with macOS 15 or later; this Mac has macOS 14.6.1"
        ),
        "{said}"
    );

    t.mac("15.6", "5.10", "1.89.0");
    let (code, said) = t.prerequisites("swift");
    assert_eq!(code, Some(2), "{said}");
    assert!(
        said.contains(
            "Swift 6 is needed and these tools have Swift 5.10; update Apple's Command Line Tools"
        ),
        "{said}"
    );

    t.mac("15.6", "6.1.2", "1.89.0");
    assert_eq!(t.prerequisites("swift"), (Some(0), String::new()));
    t.mac("26.1", "6.2", "1.91.1");
    assert_eq!(t.prerequisites("swift"), (Some(0), String::new()));
    t.tool("bin/xcode-select", "exit 1");
    let (code, said) = t.prerequisites("swift");
    assert_eq!(code, Some(2), "{said}");
    assert!(
        said.contains("install them with: xcode-select --install"),
        "{said}"
    );
}

#[test]
fn the_core_build_and_checks_need_no_swift_and_use_cargos_external_artifact() {
    let t = Tools::new("core-only");
    t.mac("15.6", "5.10", "1.89.0");
    t.checkout();
    t.tool(
        "bin/xcode-select",
        "echo 'Swift must not be requested' >&2; exit 1",
    );
    t.tool("bin/swift", "exit 1");
    t.tool("elsewhere/core with spaces", "exit 99");
    let core = t.0.join("elsewhere/core with spaces");
    let artifact = serde_json::json!({
        "reason": "compiler-artifact", "target": {"name": "immune", "kind": ["bin"]},
        "executable": core,
    });
    t.tool("bin/cargo", &format!(
        "case \"$1\" in --version) echo 'cargo 1.89.0' ;; build) echo '{}' ;; fmt|clippy|test) exit 0 ;; *) exit 1 ;; esac",
        artifact,
    ));
    let out = t.run("build", &[]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        String::from_utf8(out.stdout).unwrap().trim(),
        core.to_str().unwrap()
    );
    assert!(!t.0.join("target/app").exists());
    let out = t.run("check", &["lint", "tests"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    t.tool("bin/cargo", "echo 'cargo 1.88.0'");
    assert_eq!(t.run("build", &[]).status.code(), Some(2));
    assert_eq!(t.run("check", &["lint"]).status.code(), Some(2));
    assert_eq!(t.run("check", &["tests"]).status.code(), Some(2));
    t.tool(
        "bin/cargo",
        "case \"$1\" in --version) echo 'cargo 1.89.0' ;; esac",
    );
    assert_eq!(t.run("build", &[]).status.code(), Some(2));
}

#[test]
fn app_build_keeps_the_external_core_unchanged_and_records_its_exact_path_without_rust() {
    let t = Tools::new("app-only");
    t.mac("15.6", "6.1.2", "1.1.0");
    t.checkout();
    t.tool("bin/cargo", "echo 'Rust must not be requested' >&2; exit 1");
    t.tool("bin/ps", "exit 0");
    t.tool("bin/codesign", "exit 0");
    t.tool("built/ImmuneApp", "exit 99");
    t.tool(
        "bin/swift",
        &format!(
            "case \"$*\" in *--show-bin-path*) echo '{}' ;; esac",
            t.0.join("built").display(),
        ),
    );
    t.tool("app/test", "exit 0");
    let relative = "external/core 'quoted' & \"double\"";
    t.tool(relative, "exit 99");
    let core = t.0.join(relative);
    let before = std::fs::read(&core).unwrap();
    for args in [vec![relative], vec!["--debug", relative]] {
        let out = t.run("app/build", &args);
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let bundle = PathBuf::from(String::from_utf8(out.stdout).unwrap().trim());
        assert!(!bundle.join("Contents/MacOS/immune").exists());
        assert_eq!(std::fs::read(&core).unwrap(), before);
        let plist = Command::new("/usr/bin/plutil")
            .args(["-extract", "ImmuneExecutablePath", "raw", "-o", "-"])
            .arg(bundle.join("Contents/Info.plist"))
            .output()
            .unwrap();
        assert!(plist.status.success());
        assert_eq!(
            String::from_utf8(plist.stdout).unwrap().trim(),
            core.to_str().unwrap()
        );
    }
    let out = t.run("check", &["app"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(t.run("app/build", &["absent"]).status.code(), Some(2));
    t.mac("15.6", "5.10", "1.89.0");
    assert_eq!(t.run("app/build", &[relative]).status.code(), Some(2));
    assert_eq!(t.run("check", &["app"]).status.code(), Some(2));
}

#[test]
fn app_build_refuses_to_replace_a_bundle_containing_the_only_core() {
    let t = Tools::new("embedded-core");
    t.mac("15.6", "6.1.2", "1.89.0");
    t.checkout();
    t.tool("bin/ps", "exit 0");
    t.tool("bin/codesign", "exit 0");
    t.tool("built/ImmuneApp", "exit 99");
    t.tool(
        "bin/swift",
        &format!("echo '{}'", t.0.join("built").display()),
    );
    let bundle = "target/app/Immune.app";
    let embedded = format!("{bundle}/Contents/MacOS/immune");
    t.tool(&embedded, "exit 99");
    let core = t.0.join(&embedded);
    let original = std::fs::read(&core).unwrap();
    let marker = t.0.join(bundle).join("keep");
    std::fs::write(&marker, "old app").unwrap();
    std::os::unix::fs::symlink(&core, t.0.join("linked-core")).unwrap();
    for input in [embedded.as_str(), "linked-core"] {
        let out = t.run("app/build", &[input]);
        let reason = String::from_utf8(out.stderr).unwrap();
        assert_eq!(out.status.code(), Some(2), "{reason}");
        assert!(
            reason.contains("the core is inside the app bundle being replaced"),
            "{reason}"
        );
        assert_eq!(std::fs::read(&core).unwrap(), original);
        assert_eq!(std::fs::read_to_string(&marker).unwrap(), "old app");
    }
}

#[test]
fn app_build_refuses_to_replace_a_running_bundle_before_and_after_compiling() {
    let t = Tools::new("running-app");
    t.mac("15.6", "6.1.2", "1.89.0");
    t.checkout();
    t.tool("core", "exit 99");
    t.tool("built/ImmuneApp", "exit 99");
    t.tool("bin/codesign", "exit 0");
    let bundle = t.0.join("target/app/Immune.app");
    std::fs::create_dir_all(&bundle).unwrap();
    std::fs::write(bundle.join("keep"), "running bundle").unwrap();
    t.tool(
        "bin/ps",
        &format!("echo '{}/Contents/MacOS/ImmuneApp'", bundle.display()),
    );
    t.tool("bin/swift", "exit 99");
    assert_eq!(t.run("app/build", &["core"]).status.code(), Some(2));
    assert!(bundle.join("keep").exists());

    t.tool(
        "bin/ps",
        &format!(
            "if [ -f '{}' ]; then echo '{}/Contents/MacOS/ImmuneApp'; fi",
            t.0.join("started").display(),
            bundle.display()
        ),
    );
    t.tool(
        "bin/swift",
        &format!(
            "touch '{}'; echo '{}'",
            t.0.join("started").display(),
            t.0.join("built").display()
        ),
    );
    assert_eq!(t.run("app/build", &["core"]).status.code(), Some(2));
    assert!(bundle.join("keep").exists());
}

#[test]
fn the_tree_names_one_supported_macos_and_both_check_and_build_ask_for_it() {
    // A colleague reads the version in the README, the build checks it, the app's bundle and
    // package declare it: they must say the same.
    for script in ["check", "build"] {
        assert!(
            read(script).contains("\n. ./scripts/prerequisites.sh\n"),
            "{script}"
        );
    }
    assert!(
        read("app/Info.plist")
            .contains("<key>LSMinimumSystemVersion</key>\n\t<string>15.0</string>")
    );
    assert!(read("app/Package.swift").contains("platforms: [.macOS(.v15)]"));
    for doc in ["README.md", "CONTRIBUTING.md"] {
        let text = read(doc);
        assert!(text.contains("macOS 15 or later"), "{doc}");
        assert!(!text.contains("macOS 14"), "{doc}");
    }
}

#[test]
fn the_two_halves_of_the_tests_hold_every_test_binary_exactly_once() {
    // The check on GitHub runs `./check tests 1/2` and `./check tests 2/2` side by side in
    // place of `cargo test`: a binary in neither half would never run there.
    let half = |share: &str| {
        let out = Command::new(Path::new(ROOT).join("scripts/test-half.sh"))
            .arg(share)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap()
    };
    let mut seen: Vec<String> = format!("{}{}", half("1/2"), half("2/2"))
        .lines()
        .map(str::to_string)
        .collect();
    seen.sort();

    let mut expected: Vec<String> = std::fs::read_dir(Path::new(ROOT).join("tests"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "rs"))
        .map(|path| format!("--test {}", path.file_stem().unwrap().to_str().unwrap()))
        .chain(["--bins".to_string()])
        .collect();
    expected.sort();
    assert_eq!(seen, expected);

    // Unit tests of a library and its doc tests are not in either half.
    assert!(!Path::new(ROOT).join("src/lib.rs").exists());
    assert!(!read("Cargo.toml").contains("[lib]"));
}

#[test]
fn the_build_takes_the_binary_from_where_cargo_says_it_built_it() {
    // A target folder set in CARGO_TARGET_DIR or in a cargo configuration is not target/:
    // the path is taken from cargo's own messages, here a real build of this package.
    let cargo = Command::new(env!("CARGO"))
        .args([
            "build",
            "--locked",
            "--message-format=json-render-diagnostics",
        ])
        .current_dir(ROOT)
        .output()
        .unwrap();
    assert!(
        cargo.status.success(),
        "{}",
        String::from_utf8_lossy(&cargo.stderr)
    );
    let found = |messages: &[u8]| {
        let mut child = Command::new(Path::new(ROOT).join("scripts/cargo-built.sh"))
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        use std::io::Write;
        child.stdin.take().unwrap().write_all(messages).unwrap();
        let out = child.wait_with_output().unwrap();
        assert!(out.status.success());
        String::from_utf8(out.stdout).unwrap().trim().to_string()
    };
    assert_eq!(found(&cargo.stdout), env!("CARGO_BIN_EXE_immune"));

    // The same messages with the target folder elsewhere.
    let target = Path::new(env!("CARGO_BIN_EXE_immune"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .display()
        .to_string();
    let moved = String::from_utf8(cargo.stdout)
        .unwrap()
        .replace(&target, "/elsewhere/cargo-target");
    assert_eq!(
        found(moved.as_bytes()),
        "/elsewhere/cargo-target/debug/immune"
    );
}
