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
  if perl "$here/apply-patch.pl" "$tmp/t" "$tmp/p" >"$tmp/out" 2>&1; then bad "$1 (applied)"
  elif [ "$(cat "$tmp/t/d/f.c")" != "$(printf 'one\ntwo\nthree\nfour\nfive')" ]; then bad "$1 (tree changed)"
  else ok "$1 refused: $(head -1 "$tmp/out")"; fi
}

tree
printf 'A description line\n\n--- a/d/f.c\n+++ b/d/f.c\n@@ -2,3 +2,3 @@\n two\n-three\n+THREE\n four\n' > "$tmp/p"
if perl "$here/apply-patch.pl" "$tmp/t" "$tmp/p" >/dev/null 2>&1 && [ "$(cat "$tmp/t/d/f.c")" = "$(printf 'one\ntwo\nTHREE\nfour\nfive')" ]; then
  ok "an exact patch applies, its description skipped"
else bad "an exact patch applies"; fi

# two patches in order: the second applies to the first's result, and both or neither
tree
printf -- '--- a/d/f.c\n+++ b/d/f.c\n@@ -2,3 +2,3 @@\n two\n-three\n+THREE\n four\n' > "$tmp/p1"
printf -- '--- a/d/f.c\n+++ b/d/f.c\n@@ -3,2 +3,2 @@\n-THREE\n+3\n four\n' > "$tmp/p2"
if perl "$here/apply-patch.pl" "$tmp/t" "$tmp/p1" "$tmp/p2" >/dev/null 2>&1 && [ "$(cat "$tmp/t/d/f.c")" = "$(printf 'one\ntwo\n3\nfour\nfive')" ]; then
  ok "two patches apply in order, the second to the first's result"
else bad "two patches apply in order"; fi
tree
if perl "$here/apply-patch.pl" "$tmp/t" "$tmp/p2" "$tmp/p1" >/dev/null 2>&1; then bad "negative_patches_out_of_order (applied)"
elif [ "$(cat "$tmp/t/d/f.c")" != "$(printf 'one\ntwo\nthree\nfour\nfive')" ]; then bad "negative_patches_out_of_order (tree changed)"
else ok "negative_patches_out_of_order refused, tree untouched"; fi
tree
printf -- '--- a/d/f.c\n+++ b/d/f.c\n@@ -1,1 +1,1 @@\n-nope\n+x\n' > "$tmp/p3"
if perl "$here/apply-patch.pl" "$tmp/t" "$tmp/p1" "$tmp/p3" >/dev/null 2>&1; then bad "negative_second_patch_fails (applied)"
elif [ "$(cat "$tmp/t/d/f.c")" != "$(printf 'one\ntwo\nthree\nfour\nfive')" ]; then bad "negative_second_patch_fails (first one written)"
else ok "negative_second_patch_fails: the first is not written either"; fi

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
expect_refused "negative_insertion_past_end" $'--- a/d/f.c\n+++ b/d/f.c\n@@ -9,0 +10,1 @@\n+x\n'
expect_refused "negative_insertion_one_past_end" $'--- a/d/f.c\n+++ b/d/f.c\n@@ -6,0 +7,1 @@\n+x\n'
expect_refused "negative_format_patch_series" $'From 1 Mon Sep 17 00:00:00 2001\nSubject: [PATCH 1/2] a\n\n--- a/d/f.c\n+++ b/d/f.c\n@@ -1,1 +1,1 @@\n-one\n+ONE\n-- \n2.50.0\n\nFrom 2 Mon Sep 17 00:00:00 2001\nSubject: [PATCH 2/2] b\n\n--- a/d/f.c\n+++ b/d/f.c\n@@ -2,1 +2,1 @@\n-two\n+TWO\n'
# an insertion at the end of the file (after its last line) is exact and applies
tree
printf -- '--- a/d/f.c\n+++ b/d/f.c\n@@ -5,0 +6,1 @@\n+six\n' > "$tmp/p4"
if perl "$here/apply-patch.pl" "$tmp/t" "$tmp/p4" >/dev/null 2>&1 && [ "$(cat "$tmp/t/d/f.c")" = "$(printf 'one\ntwo\nthree\nfour\nfive\nsix')" ]; then
  ok "an insertion after the last line applies"
else bad "an insertion after the last line applies"; fi

# build.sh refuses a pinned patch whose SHA-256 differs, before it looks for the OpenSSL source
pin="$root/gradle/openssl.toml"
patch=$(sed -n 's/^patch = "\(.*\)"/\1/p' "$pin")
if [ -n "$patch" ]; then
  sed 's/^patch_sha256 = ".*"/patch_sha256 = "0000000000000000000000000000000000000000000000000000000000000000"/' "$pin" > "$tmp/pin.toml"
  if KSL_OPENSSL_PIN="$tmp/pin.toml" KSL_OPENSSL_WORK="$tmp/work" bash "$here/build.sh" macos-arm64 >"$tmp/out" 2>&1; then
    bad "negative_patch_hash_mismatch (build.sh went on)"
  elif grep -q "FAILED: $patch has SHA-256" "$tmp/out"; then ok "negative_patch_hash_mismatch refused"
  else bad "negative_patch_hash_mismatch (another error: $(head -1 "$tmp/out"))"; fi
  sed 's/^patch_2_sha256 = ".*"/patch_2_sha256 = "0000000000000000000000000000000000000000000000000000000000000000"/' "$pin" > "$tmp/pin2.toml"
  if grep -q '^patch_2 = ' "$pin"; then
    if KSL_OPENSSL_PIN="$tmp/pin2.toml" KSL_OPENSSL_WORK="$tmp/work" bash "$here/build.sh" macos-arm64 >"$tmp/out" 2>&1; then
      bad "negative_second_patch_hash_mismatch (build.sh went on)"
    elif grep -q "has SHA-256" "$tmp/out"; then ok "negative_second_patch_hash_mismatch refused"
    else bad "negative_second_patch_hash_mismatch (another error: $(head -1 "$tmp/out"))"; fi
    grep -v '^patch = \|^patch_sha256 = ' "$pin" > "$tmp/pin3.toml"
    if KSL_OPENSSL_PIN="$tmp/pin3.toml" KSL_OPENSSL_WORK="$tmp/work" bash "$here/build.sh" macos-arm64 >"$tmp/out" 2>&1; then
      bad "negative_second_patch_without_first (build.sh went on)"
    elif grep -q "patch_2 without patch" "$tmp/out"; then ok "negative_second_patch_without_first refused"
    else bad "negative_second_patch_without_first (another error: $(head -1 "$tmp/out"))"; fi
  fi
  if grep -q '^patch_3 = ' "$pin"; then
    grep -v '^patch_2 = \|^patch_2_sha256 = ' "$pin" > "$tmp/pin4.toml"
    if KSL_OPENSSL_PIN="$tmp/pin4.toml" KSL_OPENSSL_WORK="$tmp/work" bash "$here/build.sh" macos-arm64 >"$tmp/out" 2>&1; then
      bad "negative_third_patch_without_second (build.sh went on)"
    elif grep -q "patch_3 without patch_2" "$tmp/out"; then ok "negative_third_patch_without_second refused"
    else bad "negative_third_patch_without_second (another error: $(head -1 "$tmp/out"))"; fi
  fi
  for key in patch_11 patch_1 patch2 Patch_2; do # keys build.sh would not read: refused, never skipped
    { cat "$pin"; printf '%s = "tools/openssl/patches/x.patch"\n%s_sha256 = "00"\n' "$key" "$key"; } > "$tmp/pin5.toml"
    if KSL_OPENSSL_PIN="$tmp/pin5.toml" KSL_OPENSSL_WORK="$tmp/work" bash "$here/build.sh" --print-target macos-arm64 >"$tmp/out" 2>&1; then
      bad "negative_unknown_patch_key_$key (build.sh went on)"
    elif grep -q "unknown patch key" "$tmp/out"; then ok "negative_unknown_patch_key_$key refused"
    else bad "negative_unknown_patch_key_$key (another error: $(head -1 "$tmp/out"))"; fi
  done
  grep -v '^patch_sha256 = ' "$pin" > "$tmp/pin1.toml"
  if KSL_OPENSSL_PIN="$tmp/pin1.toml" KSL_OPENSSL_WORK="$tmp/work" bash "$here/build.sh" macos-arm64 >"$tmp/out" 2>&1; then
    bad "negative_patch_without_hash (build.sh went on)"
  elif grep -q "patch and patch_sha256 go together" "$tmp/out"; then ok "negative_patch_without_hash refused"
  else bad "negative_patch_without_hash (another error: $(head -1 "$tmp/out"))"; fi
  # the pinned patches' hashes are what the pin says (the files in the repository are the ones reviewed)
  for k in patch patch_2 patch_3 patch_4 patch_5 patch_6 patch_7 patch_8 patch_9 patch_10; do
    f=$(sed -n "s/^$k = \"\(.*\)\"/\1/p" "$pin"); [ -n "$f" ] || continue
    [ "$(shasum -a 256 < "$root/$f" | cut -d' ' -f1)" = "$(sed -n "s/^${k}_sha256 = \"\(.*\)\"/\1/p" "$pin")" ] \
      && ok "$k has its pinned SHA-256" || bad "$k has its pinned SHA-256"
  done
fi
[ "$fail" = 0 ] && echo "apply-patch-test: all passed" || { echo "apply-patch-test: FAILED"; exit 1; }
