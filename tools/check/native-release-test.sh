#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Negative controls of tools/check/native-release.sh on the host: a clean library passes; a sanitizer build, a library without
# the pinned OpenSSL text and (ELF hosts) one with debug sections fail. Usage: native-release-test.sh
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; root="$(cd "$here/../.." && pwd)"
ossl=$(sed -n 's/^version = "\(.*\)"/\1/p' "$root/gradle/openssl.toml")
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
plat=$([ "$(uname)" = Darwin ] && echo macos || echo linux); ext=$([ "$plat" = macos ] && echo dylib || echo so)
printf 'const char *ksl_version_text(void) { return "OpenSSL %s 29 Sep 2026"; }\n' "$ossl" > "$tmp/ok.c"
printf 'const char *ksl_version_text(void) { return "OpenSSL 0.0.0 1 Jan 2000"; }\n' > "$tmp/old.c"
CC="${CC:-cc}"; vis="-fvisibility=default"; rc=0
command -v "${CC%% *}" >/dev/null || { echo "FAIL: no C compiler ($CC)"; exit 2; }
expect() { # <0|1> <what> <lib>
  bash "$here/native-release.sh" "$3" "$plat" > "$tmp/out.txt" 2>&1; local got=$?; [ "$got" = 0 ] || got=1
  if [ "$got" = "$1" ]; then echo "ok: $2"; else echo "FAIL: $2 (exit $got)"; sed 's/^/  | /' "$tmp/out.txt"; rc=1; fi
}
$CC -shared -fPIC $vis -O2 "$tmp/ok.c" -o "$tmp/clean.$ext" && expect 0 "a clean library passes" "$tmp/clean.$ext"
$CC -shared -fPIC $vis -O1 -fsanitize=address,undefined "$tmp/ok.c" -o "$tmp/asan.$ext" && expect 1 "negative: a sanitizer build fails" "$tmp/asan.$ext"
$CC -shared -fPIC $vis -O2 "$tmp/old.c" -o "$tmp/old.$ext" && expect 1 "negative: another OpenSSL version fails" "$tmp/old.$ext"
if [ "$plat" = linux ]; then $CC -shared -fPIC $vis -O2 -g "$tmp/ok.c" -o "$tmp/debug.$ext" && expect 1 "negative: debug sections fail" "$tmp/debug.$ext"; fi
mkdir -p "$tmp/arch"; for a in libcrypto libssl libksl; do $CC -c -O1 -fsanitize=address "$tmp/ok.c" -o "$tmp/$a.o" && ar rcs "$tmp/arch/$a.a" "$tmp/$a.o" 2>/dev/null || { echo "FAIL: building the sanitized archives"; exit 2; }; done
bash "$here/native-release.sh" "$tmp/arch" archives > "$tmp/out.txt" 2>&1 && { echo "FAIL: negative: sanitized archives pass"; rc=1; } || echo "ok: negative: sanitized archives fail"
exit $rc
