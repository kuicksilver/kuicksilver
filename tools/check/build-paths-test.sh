#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Negative controls of tools/check/build-paths.py: clean artifacts pass; a home directory in a jar entry, in a jar nested
# in an AAR, in a static archive, in a klib's cstubs.bc, in a Windows DLL and in an entry name fails; so do temporary
# directories, home-relative paths, host, user and configured private names, without false positives on the forms that
# release outputs hold. Usage: build-paths-test.sh
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

# temporary directories, home-relative paths, and the names of this machine and its user (looked up at scan time;
# KSL_PRIVACY_NAMES adds names, as `git config kuicksilver.privacy.names` does on the maintainer's machine)
export KSL_PRIVACY_NAMES="zorbex-host,Zorbex Quill"
mk "$tmp/t1.a" '!<arch>\n/tmp/build-xyz/ksl.o'; expect 1 "negative: /tmp/ in a static archive" "$tmp/t1.a"
mk "$tmp/t2.so" '\x7fELF /private/tmp/k/ksl.c'; expect 1 "negative: /private/tmp/" "$tmp/t2.so"
mk "$tmp/t3.so" '\x7fELF /var/folders/6r/abc/T/ksl.c'; expect 1 "negative: /var/folders/ (macOS temp)" "$tmp/t3.so"
mk "$tmp/t4.so" '\x7fELF /private/var/folders/6r/abc/T/ksl.c'; expect 1 "negative: /private/var/folders/" "$tmp/t4.so"
mk "$tmp/t5.so" '\x7fELF /var/tmp/ksl.c'; expect 1 "negative: /var/tmp/" "$tmp/t5.so"
mk "$tmp/t6.json" '{"dir": "~/Projects/kuicksilver/build"}'; expect 1 "negative: ~/<dir>/ as text" "$tmp/t6.json"
mk "$tmp/t7.txt" 'Built on zorbex-host.'; expect 1 "negative: a host name without a path" "$tmp/t7.txt"
mk "$tmp/t8.txt" 'signed by ZORBEX QUILL'; expect 1 "negative: a configured private name, any case" "$tmp/t8.txt"
me="${USER:-$(id -un)}"
case "$(printf '%s' "$me" | tr 'A-Z' 'a-z')" in
  root|runner|admin|user|build|builder|ubuntu|docker|jenkins) echo "ok: (the user name $me is generic: not looked for)" ;;
  *) if [ ${#me} -ge 4 ]; then mk "$tmp/t9.txt" "made by $me today"; expect 1 "negative: the current user name without a path" "$tmp/t9.txt"; fi ;;
esac
host=$(hostname 2>/dev/null | cut -d. -f1)
if [ ${#host} -ge 4 ] && [ "$host" != localhost ]; then mk "$tmp/t10.txt" "compiled on $host"; expect 1 "negative: this host's name, found without configuration" "$tmp/t10.txt"; fi
mkdir -p "$tmp/fp"
mk "$tmp/fp/kdoc.txt" '/** `~/.cache/kuicksilver/` or `~/Library/Caches/kuicksilver/` */ ~/** KDoc'
mk "$tmp/fp/code.bin" '\x00~/\xa9\xcf /usr/local/tmp/x TestRunner zorbex-hostname Zorbex_Quillish'
expect 0 "no false positive: documented ~/ caches, ~/ in code, /usr/local/tmp, a name inside a longer word" "$tmp/fp"
unset KSL_PRIVACY_NAMES

[ "$rc" = 0 ] && echo "all passed" || echo "FAILED"
exit "$rc"
