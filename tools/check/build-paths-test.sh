#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Negative controls of tools/check/build-paths.py: clean artifacts pass; a home directory in a jar entry, in a jar nested
# in an AAR, in a static archive, in a klib's cstubs.bc, in a Windows DLL and in an entry name fails. Usage: build-paths-test.sh
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
rc=0
expect() { # <0|1> <what> <path>
  python3 -I "$here/build-paths.py" "$3" > "$tmp/out.txt" 2>&1; local got=$?
  if [ "$got" = "$1" ]; then echo "ok: $2"; else echo "FAIL: $2 (exit $got, want $1)"; sed 's/^/  | /' "$tmp/out.txt"; rc=1; fi
}
zipdir() { # <zip> <dir>: zips the contents of <dir>
  python3 -I -c 'import os, sys, zipfile
with zipfile.ZipFile(sys.argv[1], "w", zipfile.ZIP_DEFLATED) as z:
    for d, _, fs in os.walk(sys.argv[2]):
        for f in fs: z.write(os.path.join(d, f), os.path.relpath(os.path.join(d, f), sys.argv[2]))' "$1" "$2"
}
mk() { mkdir -p "$(dirname "$1")"; printf '%b' "$2" > "$1"; }

mk "$tmp/clean/x/io/A.class" '\xca\xfe\xba\xbe relative/path/A.kt kuicksilver-native/src/c/ksl.c'
mk "$tmp/clean/x/lib.a" '!<arch>\n./crypto/x.c compiler: cc -fPIC -Os'
zipdir "$tmp/clean/ok.jar" "$tmp/clean/x"; rm -rf "$tmp/clean/x"
expect 0 "clean artifacts pass" "$tmp/clean"

mk "$tmp/j/io/A.class" '\xca\xfe\xba\xbe /Users/someone/src/A.kt'; zipdir "$tmp/home.jar" "$tmp/j"
expect 1 "negative: /Users/ in a jar entry" "$tmp/home.jar"

mk "$tmp/c/io/B.class" '\xca\xfe /home/builder/w/B.kt'; mkdir -p "$tmp/aar"; zipdir "$tmp/aar/classes.jar" "$tmp/c"
mk "$tmp/aar/AndroidManifest.xml" '<manifest/>'; zipdir "$tmp/nested.aar" "$tmp/aar"
expect 1 "negative: /home/ in a jar inside an AAR" "$tmp/nested.aar"

mk "$tmp/win.a" '!<arch>\ncompiler: C:\\Users\\builder\\mingw\\bin\\gcc.exe -O2'
expect 1 "negative: C:\\Users in a static archive" "$tmp/win.a"

mk "$tmp/k/default/targets/mingw_x64/native/cstubs.bc" 'BC\xc0\xde /Users/someone/checkout/kuicksilver-native clang'
zipdir "$tmp/cinterop.klib" "$tmp/k"
expect 1 "negative: a compilation directory in a klib's cstubs.bc" "$tmp/cinterop.klib"

mk "$tmp/x.dll" 'MZ\x90\x00 C:/Users/builder/ksl.c'
expect 1 "negative: C:/Users in a DLL" "$tmp/x.dll"

mk "$tmp/lower.dll" 'MZ\x90\x00 d:\\users\\builder\\ksl.c'
expect 1 "negative: d:\\users in any case" "$tmp/lower.dll"

mk "$tmp/prov/statement.json" '{"host": {"os": "Darwin arm64"}, "src": "/home/builder/w"}'
expect 1 "negative: a home directory in a provenance statement" "$tmp/prov/statement.json"

mkdir -p "$tmp/n3"
python3 -I -c 'import sys, zipfile
with zipfile.ZipFile(sys.argv[1], "w") as z: z.writestr("/Users/someone/leak.txt", "x")' "$tmp/n3/names.zip"
expect 1 "negative: a home directory as an entry name" "$tmp/n3/names.zip"

[ "$rc" = 0 ] && echo "all passed" || echo "FAILED"
exit "$rc"
