# Sourced by build and check: the platform, then each part asks for its tools.
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

rust_prerequisites() {
  rust_hint="install Rust from https://rustup.rs (the official page) or with: brew install rustup && rustup default stable"
  command -v cargo >/dev/null 2>&1 || missing "cargo, Rust's build tool, is not found; $rust_hint"
  cargo_version=$(cargo --version 2>/dev/null) ||
    missing "cargo is there but has no toolchain to run; install the one rust-toolchain.toml names with: rustup toolchain install"
  # The locked rusqlite declares Rust 1.89 as its minimum, and the store uses File::try_lock,
  # stable since that release. Cargo.toml says the same, so cargo refuses an older one too.
  minor=$(echo "$cargo_version" | sed -n 's/^cargo 1\.\([0-9]*\)\..*/\1/p')
  [ "${minor:-0}" -ge 89 ] ||
    missing "Rust 1.89 or later is needed and this is $cargo_version; update with: rustup update stable"
}
