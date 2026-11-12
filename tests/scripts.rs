//! Promises of the scripts that build and check the program on a colleague's Mac: what they
//! ask of the Mac is said once and asked by both, and the build finds the binary where cargo
//! put it. The scripts run here against invented tools; `./build` itself is never run.

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
        Tools(dir)
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

    /// The prerequisites as `./check` and `./build` source them: the exit code and stderr.
    fn prerequisites(&self) -> (Option<i32>, String) {
        let out = Command::new("/bin/sh")
            .arg("-c")
            .arg(". ./scripts/prerequisites.sh")
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
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn building_and_checking_refuse_a_mac_older_than_macos_15_or_tools_without_swift_6_and_say_what_to_install()
 {
    // macOS 14 has no /usr/bin/jq, which the collector and tests need, and its Command Line
    // Tools carry no Swift 6, which the app's package asks for.
    let t = Tools::new("prerequisites");
    t.mac("14.6.1", "6.0.3", "1.89.0");
    let (code, said) = t.prerequisites();
    assert_eq!(code, Some(2), "{said}");
    assert!(
        said.contains(
            "only on Apple Silicon Macs with macOS 15 or later; this Mac has macOS 14.6.1"
        ),
        "{said}"
    );

    t.mac("15.6", "5.10", "1.89.0");
    let (code, said) = t.prerequisites();
    assert_eq!(code, Some(2), "{said}");
    assert!(
        said.contains(
            "Swift 6 is needed and these tools have Swift 5.10; update Apple's Command Line Tools"
        ),
        "{said}"
    );

    t.mac("15.6", "6.1.2", "1.89.0");
    assert_eq!(t.prerequisites(), (Some(0), String::new()));
    t.mac("26.1", "6.2", "1.91.1");
    assert_eq!(t.prerequisites(), (Some(0), String::new()));
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
