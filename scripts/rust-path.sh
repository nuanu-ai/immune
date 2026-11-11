# Sourced by check and build: where cargo usually is when no shell profile has put it
# on PATH. rustup's own install, then Homebrew's rustup and rust on Apple Silicon.
# They go after PATH, so a toolchain the person chose first still wins.
# RUST_PLACES replaces the list, so a test can show what happens without cargo.
rust_places=${RUST_PLACES-$HOME/.cargo/bin:/opt/homebrew/opt/rustup/bin:/opt/homebrew/bin}
if [ -n "$rust_places" ]; then
  PATH="$PATH:$rust_places"
fi
export PATH
