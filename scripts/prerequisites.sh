# Sourced by check and build after rust-path.sh: what building and testing need on this Mac.
# Each missing thing is said with how to install it, and the script exits 2; nothing is
# installed and nothing is asked.

missing() {
  echo "$(basename "$0"): $1" >&2
  exit 2
}

# The program is built and tested only on Apple Silicon with macOS 15 or later.
only="this program is built and tested only on Apple Silicon Macs with macOS 15 or later"
[ "$(uname -s)" = Darwin ] && [ "$(uname -m)" = arm64 ] || missing "$only."
macos=$(sw_vers -productVersion)
[ "${macos%%.*}" -ge 15 ] || missing "$only; this Mac has macOS $macos."

# Asking xcode-select where the tools are never raises the install dialog that
# running /usr/bin/swift without them would.
dev=$(xcode-select -p 2>/dev/null) || dev=
swift=
for candidate in "$dev/usr/bin/swift" "$dev/Toolchains/XcodeDefault.xctoolchain/usr/bin/swift"; do
  if [ -x "$candidate" ]; then
    swift=$candidate
    break
  fi
done
[ -n "$swift" ] ||
  missing "Apple's Command Line Tools with swift are missing; install them with: xcode-select --install"
# app/Package.swift is written for Swift 6.
swift_version=$("$swift" --version 2>&1 | sed -n 's/.*Apple Swift version \([0-9][0-9.]*\).*/\1/p' | head -n 1)
[ "${swift_version%%.*}" = 6 ] ||
  missing "Swift 6 is needed and these tools have Swift ${swift_version:-of an unknown version}; update Apple's Command Line Tools in System Settings, General, Software Update, or install Xcode 16 or later"

rust_hint="install Rust from https://rustup.rs (the official page) or with: brew install rustup && rustup default stable"
command -v cargo >/dev/null 2>&1 || missing "cargo, Rust's build tool, is not found; $rust_hint"
cargo_version=$(cargo --version 2>/dev/null) ||
  missing "cargo is there but has no toolchain to run; install the one rust-toolchain.toml names with: rustup toolchain install"
# The locked rusqlite declares Rust 1.89 as its minimum, and the store uses File::try_lock,
# stable since that release. Cargo.toml says the same, so cargo refuses an older one too.
minor=$(echo "$cargo_version" | sed -n 's/^cargo 1\.\([0-9]*\)\..*/\1/p')
[ "${minor:-0}" -ge 89 ] ||
  missing "Rust 1.89 or later is needed and this is $cargo_version; update with: rustup update stable"
