#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Self-test of tools/openssl/apply-patch.pl (the carried OpenSSL patch, ADR-0019) and of build.sh's check of the patch's
# pinned SHA-256: a patch applies exactly, and every inexact one is refused with the tree left as it was. No OpenSSL source
# is needed. Usage: tools/openssl/apply-patch-test.sh
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; root="$here/../.."
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT INT TERM HUP
fail=0
ok() { echo "ok: $1"; }
bad() { echo "FAIL: $1"; fail=1; }
tree() { rm -rf "$tmp/t"; mkdir -p "$tmp/t/d"; printf 'one\ntwo\nthree\nfour\nfive\n' > "$tmp/t/d/f.c"; }
expect_refused() { # <name> <patch text>: refused, and the file unchanged
  tree; printf '%s' "$2" > "$tmp/p"
  if perl "$here/apply-patch.pl" "$tmp/p" "$tmp/t" >"$tmp/out" 2>&1; then bad "$1 (applied)"
  elif [ "$(cat "$tmp/t/d/f.c")" != "$(printf 'one\ntwo\nthree\nfour\nfive')" ]; then bad "$1 (tree changed)"
  else ok "$1 refused: $(head -1 "$tmp/out")"; fi
}

tree
printf 'A description line\n\n--- a/d/f.c\n+++ b/d/f.c\n@@ -2,3 +2,3 @@\n two\n-three\n+THREE\n four\n' > "$tmp/p"
if perl "$here/apply-patch.pl" "$tmp/p" "$tmp/t" >/dev/null 2>&1 && [ "$(cat "$tmp/t/d/f.c")" = "$(printf 'one\ntwo\nTHREE\nfour\nfive')" ]; then
  ok "an exact patch applies, its description skipped"
else bad "an exact patch applies"; fi

expect_refused "negative_context_differs" $'--- a/d/f.c\n+++ b/d/f.c\n@@ -2,3 +2,3 @@\n two\n-tree\n+THREE\n four\n'
expect_refused "negative_offset_hunk" $'--- a/d/f.c\n+++ b/d/f.c\n@@ -3,3 +3,3 @@\n two\n-three\n+THREE\n four\n'
expect_refused "negative_counts_wrong" $'--- a/d/f.c\n+++ b/d/f.c\n@@ -2,4 +2,3 @@\n two\n-three\n+THREE\n four\n'
expect_refused "negative_renamed_file" $'--- a/d/f.c\n+++ b/d/g.c\n@@ -2,3 +2,3 @@\n two\n-three\n+THREE\n four\n'
expect_refused "negative_path_traversal" $'--- a/../f.c\n+++ b/../f.c\n@@ -2,3 +2,3 @@\n two\n-three\n+THREE\n four\n'
expect_refused "negative_no_newline_marker" $'--- a/d/f.c\n+++ b/d/f.c\n@@ -2,3 +2,3 @@\n two\n-three\n\\ No newline at end of file\n+THREE\n four\n'
expect_refused "negative_second_hunk_fails" $'--- a/d/f.c\n+++ b/d/f.c\n@@ -1,1 +1,1 @@\n-one\n+ONE\n@@ -5,1 +5,1 @@\n-FIVE\n+5\n'
expect_refused "negative_overlapping_hunks" $'--- a/d/f.c\n+++ b/d/f.c\n@@ -2,2 +2,2 @@\n-two\n+TWO\n three\n@@ -3,1 +3,1 @@\n-three\n+3\n'
expect_refused "negative_missing_file" $'--- a/d/none.c\n+++ b/d/none.c\n@@ -1,1 +1,1 @@\n-one\n+ONE\n'
expect_refused "negative_no_file_in_patch" $'only a description\n'

# build.sh refuses a pinned patch whose SHA-256 differs, before it looks for the OpenSSL source
pin="$root/gradle/openssl.toml"
patch=$(sed -n 's/^patch = "\(.*\)"/\1/p' "$pin")
if [ -n "$patch" ]; then
  sed 's/^patch_sha256 = ".*"/patch_sha256 = "0000000000000000000000000000000000000000000000000000000000000000"/' "$pin" > "$tmp/pin.toml"
  if KSL_OPENSSL_PIN="$tmp/pin.toml" KSL_OPENSSL_WORK="$tmp/work" bash "$here/build.sh" macos-arm64 >"$tmp/out" 2>&1; then
    bad "negative_patch_hash_mismatch (build.sh went on)"
  elif grep -q "FAILED: $patch has SHA-256" "$tmp/out"; then ok "negative_patch_hash_mismatch refused"
  else bad "negative_patch_hash_mismatch (another error: $(head -1 "$tmp/out"))"; fi
  grep -v '^patch_sha256 = ' "$pin" > "$tmp/pin1.toml"
  if KSL_OPENSSL_PIN="$tmp/pin1.toml" KSL_OPENSSL_WORK="$tmp/work" bash "$here/build.sh" macos-arm64 >"$tmp/out" 2>&1; then
    bad "negative_patch_without_hash (build.sh went on)"
  elif grep -q "patch and patch_sha256 go together" "$tmp/out"; then ok "negative_patch_without_hash refused"
  else bad "negative_patch_without_hash (another error: $(head -1 "$tmp/out"))"; fi
  # the pinned patch's hash is what the pin says (the file in the repository is the one reviewed)
  [ "$(shasum -a 256 < "$root/$patch" | cut -d' ' -f1)" = "$(sed -n 's/^patch_sha256 = "\(.*\)"/\1/p' "$pin")" ] \
    && ok "the pinned patch has its pinned SHA-256" || bad "the pinned patch has its pinned SHA-256"
fi
[ "$fail" = 0 ] && echo "apply-patch-test: all passed" || { echo "apply-patch-test: FAILED"; exit 1; }
