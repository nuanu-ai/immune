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

    /// A Mac with this macOS and this cargo.
    fn mac(&self, macos: &str, cargo: &str) {
        self.tool(
            "bin/uname",
            "case \"$1\" in -s) echo Darwin ;; -m) echo arm64 ;; esac",
        );
        self.tool("bin/sw_vers", &format!("echo {macos}"));
        self.tool("bin/cargo", &format!("echo 'cargo {cargo} (2025-01-01)'"));
    }

    fn checkout(&self) {
        for rel in [
            "build",
            "check",
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
fn the_checks_refuse_an_old_macos_and_say_which_is_needed() {
    // macOS 14 has no /usr/bin/jq, which the collector and tests need.
    let t = Tools::new("prerequisites");
    t.mac("14.6.1", "1.89.0");
    let (code, said) = t.prerequisites("rust");
    assert_eq!(code, Some(2), "{said}");
    assert!(
        said.contains(
            "only on Apple Silicon Macs with macOS 15 or later; this Mac has macOS 14.6.1"
        ),
        "{said}"
    );

    t.mac("15.6", "1.89.0");
    assert_eq!(t.prerequisites("rust"), (Some(0), String::new()));
    t.mac("26.1", "1.91.1");
    assert_eq!(t.prerequisites("rust"), (Some(0), String::new()));
}

#[test]
fn the_core_build_and_checks_use_cargos_external_artifact() {
    let t = Tools::new("core-only");
    t.mac("15.6", "1.89.0");
    t.checkout();
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
fn the_tree_names_one_supported_macos_and_both_check_and_build_ask_for_it() {
    // A colleague reads the version in the README and the build checks it: they must say the
    // same.
    for script in ["check", "build"] {
        assert!(
            read(script).contains("\n. ./scripts/prerequisites.sh\n"),
            "{script}"
        );
    }
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
