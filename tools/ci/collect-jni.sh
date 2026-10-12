#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Gathers the JVM native libraries of every platform into the kuicksilver-native jar resources, for the jar CI publishes.
# Each platform job uploads the output directory of tools/build-jni.sh as the artifact jni-<classifier>; downloaded into
# <artifacts>/jni-<classifier>/, every library is checked against its own job's manifest.sha256, copied to
# kuicksilver-native/build/jni/resources/META-INF/native/, and one manifest.sha256 is written over all of them.
# Then build the jar with -x :kuicksilver-native:buildJniHost (it would replace the host library with a local build) and
# check it with: collect-jni.sh --check-jar <jar>.
# Usage: collect-jni.sh <artifacts dir> | collect-jni.sh --check-jar <kuicksilver-native-jvm jar>
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
abi=$(sed -n 's/^#define KSL_ABI_VERSION \([0-9]*\)u/\1/p' "$root/kuicksilver-native/src/c/ksl.h")
# classifier -> library: osx-x86_64 is the JVM on Intel Macs (no Kotlin/Native macosX64), windows-x86_64 the mingw-w64 dll
libs="linux-x86_64:libksl_${abi}_linux_x86_64.so linux-aarch_64:libksl_${abi}_linux_aarch_64.so osx-aarch_64:libksl_${abi}_osx_aarch_64.dylib osx-x86_64:libksl_${abi}_osx_x86_64.dylib windows-x86_64:libksl_${abi}_windows_x86_64.dll"
sha() { (sha256sum "$@" 2>/dev/null || shasum -a 256 "$@"); }
if [ "${1:-}" = "--check-jar" ]; then
  jar="${2:?jar}"; listing=$(unzip -l "$jar"); rc=0
  for e in $libs manifest:manifest.sha256; do
    printf '%s\n' "$listing" | grep -qE " META-INF/native/${e#*:}\$" || { echo "FAIL: META-INF/native/${e#*:} missing in $jar"; rc=1; }
  done
  [ "$rc" = 0 ] && echo "OK: $jar carries libksl for $(for e in $libs; do printf '%s ' "${e%%:*}"; done)"
  exit "$rc"
fi
art="${1:?artifacts dir}"; dst="$root/kuicksilver-native/build/jni/resources/META-INF/native"
rm -rf "$dst"; mkdir -p "$dst"
for e in $libs; do
  cls="${e%%:*}"; lib="${e#*:}"; d="$art/jni-$cls/resources/META-INF/native"
  [ -f "$d/$lib" ] || { echo "FAIL: $lib missing in artifact jni-$cls (found: $(cd "$d" 2>/dev/null && echo *))" >&2; exit 1; }
  want=$(awk -v f="$lib" '$2 == f || $2 == "*"f {print $1}' "$d/manifest.sha256" 2>/dev/null || true)
  got=$(sha "$d/$lib" | cut -d' ' -f1)
  [ -n "$want" ] && [ "$want" = "$got" ] || { echo "FAIL: $lib sha256 $got, its job's manifest says '${want:-nothing}'" >&2; exit 1; }
  cp "$d/$lib" "$dst/$lib"; echo "$cls: $lib ($(wc -c < "$dst/$lib" | tr -d ' ') bytes)"
done
( cd "$dst" && sha libksl_* > manifest.sha256 )
