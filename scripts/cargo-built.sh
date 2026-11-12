#!/bin/sh
# Prints the path of the immune binary that cargo says it built, from cargo's JSON messages
# on stdin (`cargo build --message-format=json-render-diagnostics`). A target folder set in
# CARGO_TARGET_DIR or in a cargo configuration is not target/, so the path is cargo's.
# Prints nothing when cargo named none.
set -eu
/usr/bin/jq -r 'select(.reason == "compiler-artifact" and .target.name == "immune"
  and (.target.kind | index("bin")) and .executable != null) | .executable'
