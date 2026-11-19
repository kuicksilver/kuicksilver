#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Negative controls of tools/openssl/brotli-pin-check.sh against a local fixture repository (no network): a tarball made by
# `git archive` of the tagged commit and pinned with its SHA-256 passes; a tag that moved to another commit, a tarball with one
# file changed (pinned with its own SHA-256, as a forged release would be), one with an extra file, one with a file's mode
# changed, and a tarball whose bytes are not the pinned SHA-256 are each refused. Usage: brotli-pin-check-test.sh
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
tmp=$(mktemp -d "${TMPDIR:-/tmp}/ksl-brotli-pin-test.XXXXXX"); trap 'rm -rf "$tmp"' EXIT INT TERM HUP
export GIT_CONFIG_NOSYSTEM=1 HOME="$tmp/home"; mkdir -p "$HOME"
g() { git -C "$tmp/src" -c user.name=t -c user.email=t@example.invalid -c commit.gpgsign=false -c tag.gpgsign=false "$@"; }
mkdir -p "$tmp/src/c/dec"; git init -q "$tmp/src"
printf 'int decode(void) { return 1; }\n' > "$tmp/src/c/dec/decode.c"; printf '#!/bin/sh\necho ok\n' > "$tmp/src/build.sh"; chmod +x "$tmp/src/build.sh"
g add -A; g commit -q -m one; g tag v9.9.9; c1=$(g rev-parse HEAD)
printf 'int decode(void) { return 2; }\n' > "$tmp/src/c/dec/decode.c"; g commit -q -am two; c2=$(g rev-parse HEAD)
sum() { if command -v sha256sum >/dev/null 2>&1; then sha256sum < "$1" | cut -d' ' -f1; else shasum -a 256 < "$1" | cut -d' ' -f1; fi; }
pin() { printf '[brotli]\nversion = "9.9.9"\nsha256 = "%s"\ncommit = "%s"\n' "$(sum "$2")" "$3" > "$1"; }
archive() { git -C "$tmp/src" archive --format=tar --prefix=brotli-9.9.9/ "$1" | gzip -n > "$2"; }
retar() { # <tarball> <function that edits the unpacked brotli-9.9.9/>
  rm -rf "$tmp/x"; mkdir -p "$tmp/x"; tar xzf "$1" -C "$tmp/x"; "$2" "$tmp/x/brotli-9.9.9"; (cd "$tmp/x" && tar cf - brotli-9.9.9 | gzip -n > "$1")
}
rc=0
case_() { # <name> <0|1> <tarball> <toml> [expected message]
  local out got; out=$(bash "$here/brotli-pin-check.sh" --repo "$tmp/src" --tarball "$3" --toml "$4" 2>&1); got=$?; [ "$got" = 0 ] || got=1
  if [ "$got" = "$2" ] && { [ -z "${5:-}" ] || grep -qF "$5" <<< "$out"; }; then echo "ok: $1"; else echo "FAIL: $1 (exit $got)"; sed 's/^/  | /' <<< "$out"; rc=1; fi
}
archive "$c1" "$tmp/good.tar.gz"; pin "$tmp/good.toml" "$tmp/good.tar.gz" "$c1"
case_ "the archive of the tagged commit passes" 0 "$tmp/good.tar.gz" "$tmp/good.toml"
pin "$tmp/other.toml" "$tmp/good.tar.gz" "$c2"
case_ "negative_tagNotThePinnedCommit" 1 "$tmp/good.tar.gz" "$tmp/other.toml" "is commit $c1"
cp "$tmp/good.tar.gz" "$tmp/changed.tar.gz"; edit_file() { printf 'int decode(void) { return 3; }\n' > "$1/c/dec/decode.c"; }
retar "$tmp/changed.tar.gz" edit_file; pin "$tmp/changed.toml" "$tmp/changed.tar.gz" "$c1"
case_ "negative_fileChangedInTheTarball" 1 "$tmp/changed.tar.gz" "$tmp/changed.toml" "bytes differ"
cp "$tmp/good.tar.gz" "$tmp/extra.tar.gz"; add_file() { printf 'x\n' > "$1/c/dec/planted.c"; }
retar "$tmp/extra.tar.gz" add_file; pin "$tmp/extra.toml" "$tmp/extra.tar.gz" "$c1"
case_ "negative_extraFileInTheTarball" 1 "$tmp/extra.tar.gz" "$tmp/extra.toml" "not the tree"
cp "$tmp/good.tar.gz" "$tmp/mode.tar.gz"; drop_x() { chmod -x "$1/build.sh"; }
retar "$tmp/mode.tar.gz" drop_x; pin "$tmp/mode.toml" "$tmp/mode.tar.gz" "$c1"
case_ "negative_modeChangedInTheTarball" 1 "$tmp/mode.tar.gz" "$tmp/mode.toml" "not the tree"
case_ "negative_tarballNotThePinnedSha256" 1 "$tmp/changed.tar.gz" "$tmp/good.toml" "is pinned"
exit $rc
