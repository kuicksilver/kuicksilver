#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# The Windows x64 JVM library (libksl_<abi>_windows_x86_64.dll), cross-built by tools/build-jni.sh with mingw-w64 in the
# kuicksilver-openssl-mingw image against build/openssl/mingw-x64, with the JNI headers of the Windows JDK pinned in
# gradle/toolchains.toml [windows] (only include/ is kept, in build/jdk-windows), then the export whitelist.
# Usage: jni-windows.sh [out dir relative to the repository root, default build/jni-windows]
# Output as tools/build-jni.sh: <out>/windows-x86_64/<dll> and <out>/resources/META-INF/native/{<dll>,manifest.sha256}.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"; cd "$root"
out="${1:-build/jni-windows}"
case "$out" in /*|*..*) echo "out dir must be inside the repository, relative (it is mounted at /w)" >&2; exit 2 ;; esac
url=$(sed -n 's/^jdk-url = "\(.*\)".*/\1/p' gradle/toolchains.toml); sha=$(sed -n 's/^jdk-sha256 = "\(.*\)".*/\1/p' gradle/toolchains.toml)
[ -n "$url" ] && [ -n "$sha" ] || { echo "no [windows] jdk-url / jdk-sha256 in gradle/toolchains.toml" >&2; exit 2; }
[ -f build/openssl/mingw-x64/lib/libcrypto.a ] || { echo "OpenSSL for mingw-x64 not built (build/openssl/mingw-x64)" >&2; exit 2; }
jh=build/jdk-windows
if [ "$(cat "$jh/.sha256" 2>/dev/null || true)" != "$sha" ]; then
  rm -rf "$jh" build/jdk-windows.tmp build/jdk-windows.zip; mkdir -p "$jh" build/jdk-windows.tmp
  curl -fsSL --retry 3 -o build/jdk-windows.zip "$url"
  got=$( (sha256sum build/jdk-windows.zip 2>/dev/null || shasum -a 256 build/jdk-windows.zip) | cut -d' ' -f1)
  [ "$got" = "$sha" ] || { echo "Windows JDK zip: sha256 $got, pinned $sha" >&2; exit 1; }
  unzip -q build/jdk-windows.zip '*/include/*' -d build/jdk-windows.tmp
  mv build/jdk-windows.tmp/*/include "$jh/include"; rm -rf build/jdk-windows.tmp build/jdk-windows.zip
  [ -f "$jh/include/jni.h" ] && [ -f "$jh/include/win32/jni_md.h" ] || { echo "no JNI headers in the Windows JDK zip" >&2; exit 1; }
  echo "$sha" > "$jh/.sha256"
fi
bash tools/openssl/build-docker.sh --image mingw-x64
# exports.sh lists the symbol table of the stripped dll (llvm-nm), objdump -p the export directory the JVM actually resolves
bash tools/ci/docker-run.sh linux/amd64 kuicksilver-openssl-mingw "set -e; JAVA_HOME=/w/$jh bash tools/build-jni.sh windows-x86_64 $out
  dll=\$(ls $out/windows-x86_64/libksl_*_windows_x86_64.dll)
  bash tools/check/exports.sh \"\$dll\" windows \"\$(command -v llvm-nm)\"
  x86_64-w64-mingw32-objdump -p \"\$dll\" | grep -q 'JNI_OnLoad_ksl' || { echo \"FAIL: JNI_OnLoad_ksl not in the export directory of \$dll\"; exit 1; }"
