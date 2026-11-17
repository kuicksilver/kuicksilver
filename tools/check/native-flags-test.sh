#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Negative controls of the builder's compiler and flags in the native build scripts (docs/guide/building.md):
#   1. tools/openssl/build.sh, against a stub OpenSSL source tree and a stub make (no compiler runs): CPPFLAGS, CFLAGS and
#      LDFLAGS reach Configure as options after the project's own, in that order, and never through its environment
#      (where Configure would put them in place of the target's flags); configure-target.txt, provenance.txt and
#      --print-target name them; the cache key tells builds with and without them apart; Configure's own options, words
#      that are not flags and %-escapes are refused before anything runs.
#   2. tools/build-ksl-a.sh and tools/build-jni.sh (macOS, on a copy of the tree): a CC wrapper records every compiler
#      invocation: CC is the compiler, every project flag is still there and the builder's come after them (CPPFLAGS and
#      CFLAGS after -Werror, LDFLAGS after the export list), a flag that cannot compile fails the build, LDFLAGS reach the
#      linker (a link map is written) and the library still exports only its entry points.
#   3. tools/check/double-build.sh (macOS) builds with the project's own compiler and flags: with a CC that does not exist
#      and flags that cannot compile in the environment, it still builds and finds the two builds identical.
# Parts 2 and 3 need a macOS host and build/openssl/macos-arm64; elsewhere they are reported as skipped.
# Usage: tools/check/native-flags-test.sh
set -uo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
tmp="$root/build/native-flags-test"; rm -rf "$tmp"; mkdir -p "$tmp"
unset CC CPPFLAGS CFLAGS CXXFLAGS LDFLAGS LDLIBS
fails=0; passes=0
pass() { echo "PASS $1"; passes=$((passes + 1)); }
fail() { echo "FAIL $1${2:+: $2}"; fails=$((fails + 1)); }
check() { if [ "$2" = 0 ]; then pass "$1"; else fail "$1" "${3:-}"; fi; }   # <name> <0 = ok> [detail]
# index of the first line equal to <word> in <file>, or -1
pos() { awk -v w="$2" '$0 == w { print NR; f = 1; exit } END { if (!f) print -1 }' "$1"; }

# ---------------------------------------------------------------------------------------------- 1. tools/openssl/build.sh
version=$(sed -n 's/^version = "\(.*\)"/\1/p' "$root/gradle/openssl.toml")
work="$tmp/openssl-work"; src="$work/src/openssl-$version"; stub="$tmp/stub-bin"; log="$tmp/configure"
mkdir -p "$src/util" "$src/include/openssl" "$stub"
echo '#define OPENSSL_VERSION_STR "stub"' > "$src/include/openssl/opensslv.h"
cat > "$src/Configure" <<'EOF'
#!/bin/sh
# records what OpenSSL's Configure would get: its arguments and its environment
printf '%s\n' "$@" > "$KSL_FLAGS_TEST_LOG.args"; env > "$KSL_FLAGS_TEST_LOG.env"
EOF
cat > "$src/util/mkbuildinf.pl" <<'EOF'
print "/* stub buildinf.h */\n";
EOF
# the layout of OpenSSL's crypto/buildinf.h that build.sh rewrites: a PLATFORM define and one character literal per character
cat > "$stub/make" <<'EOF'
#!/bin/sh
case "$*" in
  *crypto/buildinf.h*) mkdir -p crypto
    printf '#define PLATFORM "platform: stub"\nstatic const char compiler_flags[] = {\n    %s\n};\n' \
      "'c','o','m','p','i','l','e','r',':',' ','c','c','\\0'" > crypto/buildinf.h ;;
  *build_libs*) printf 'stub' > libcrypto.a; printf 'stub' > libssl.a ;;
esac
EOF
chmod +x "$src/Configure" "$stub/make"
ossl() { # <out dir> [VAR=value ...]: tools/openssl/build.sh linux-x64 against the stubs; prints its output
  local out="$1"; shift
  env PATH="$stub:$PATH" KSL_OPENSSL_WORK="$work" KSL_OPENSSL_OUT="$out" KSL_FLAGS_TEST_LOG="$log" "$@" \
    bash "$root/tools/openssl/build.sh" linux-x64 2>&1
}
portable() { tr ' ' '\n' | grep -v '/' | grep -v '^$' | tr '\n' ' ' | sed 's/ $//'; }
F_CPP="-DKSL_FLAGS_PROBE_CPP=1"; F_C="-fstack-protector-strong"; F_LD="-Wl,-z,relro"

rm -f "$log".*; out=$(ossl "$tmp/o1"); rc=$?
check "openssl: builds without the builder's flags" "$([ $rc = 0 ] && grep -q '^built linux-x64' <<< "$out" && echo 0 || echo 1)" "$out"
check "openssl: without them Configure ends with the project's flags" "$([ "$(tail -1 "$log.args")" = -fno-common ] && echo 0 || echo 1)" "last: $(tail -1 "$log.args")"
t1=$(portable < "$tmp/o1/linux-x64/configure-target.txt")
check "openssl: configure-target.txt without them is unchanged" "$([ "$t1" = "linux-x86_64 -Os" ] && echo 0 || echo 1)" "$t1"

rm -f "$log".*; out=$(ossl "$tmp/o2" CPPFLAGS="$F_CPP" CFLAGS="$F_C" LDFLAGS="$F_LD"); rc=$?
check "openssl: builds with the builder's flags, not from the cache of a build without them" \
  "$([ $rc = 0 ] && grep -q '^built linux-x64' <<< "$out" && echo 0 || echo 1)" "$out"
p_vis=$(pos "$log.args" -fvisibility=hidden); p_nc=$(pos "$log.args" -fno-common)
p_cpp=$(pos "$log.args" "$F_CPP"); p_c=$(pos "$log.args" "$F_C"); p_ld=$(pos "$log.args" "$F_LD")
check "openssl: Configure gets CPPFLAGS, CFLAGS and LDFLAGS after the project's flags, in that order" \
  "$([ "$p_vis" -gt 0 ] && [ "$p_nc" -gt 0 ] && [ "$p_cpp" -gt "$p_nc" ] && [ "$p_c" -gt "$p_cpp" ] && [ "$p_ld" -gt "$p_c" ] && echo 0 || echo 1)" \
  "positions: -fvisibility=hidden $p_vis, -fno-common $p_nc, CPPFLAGS $p_cpp, CFLAGS $p_c, LDFLAGS $p_ld"
check "negative_configureEnvironmentHasNoBuilderFlags" \
  "$([ -s "$log.env" ] && ! grep -qE '^(CPPFLAGS|CFLAGS|CXXFLAGS|LDFLAGS|LDLIBS)=' "$log.env" && echo 0 || echo 1)" "$(grep -E '^(CPPFLAGS|CFLAGS|LDFLAGS)=' "$log.env")"
t2=$(portable < "$tmp/o2/linux-x64/configure-target.txt")
check "openssl: configure-target.txt names the builder's flags" "$([ "$t2" = "linux-x86_64 -Os $F_CPP $F_C $F_LD" ] && echo 0 || echo 1)" "$t2"
check "openssl: provenance.txt names them" "$(grep -qxF "target $t2" "$tmp/o2/linux-x64/provenance.txt" && echo 0 || echo 1)"
pt=$(CPPFLAGS="$F_CPP" CFLAGS="$F_C" LDFLAGS="$F_LD" bash "$root/tools/openssl/build.sh" --print-target linux-x64)
check "openssl: --print-target says what was configured, with the flags" "$([ "$pt" = "$t2" ] && echo 0 || echo 1)" "'$pt' vs '$t2'"
pt=$(bash "$root/tools/openssl/build.sh" --print-target linux-x64)
check "openssl: --print-target says what was configured, without them" "$([ "$pt" = "$t1" ] && echo 0 || echo 1)" "'$pt' vs '$t1'"
out=$(ossl "$tmp/o3" CPPFLAGS="$F_CPP" CFLAGS="$F_C" LDFLAGS="$F_LD")
check "openssl: the same flags again take their own cache" "$(grep -q '^cache hit' <<< "$out" && echo 0 || echo 1)" "$out"
check "openssl: ... which names them" "$([ "$(portable < "$tmp/o3/linux-x64/configure-target.txt")" = "$t2" ] && echo 0 || echo 1)"
out=$(ossl "$tmp/o4")
check "negative_cacheOfFlaggedBuildNotReusedWithout" \
  "$(grep -q '^cache hit' <<< "$out" && [ "$(portable < "$tmp/o4/linux-x64/configure-target.txt")" = "$t1" ] && echo 0 || echo 1)" "$out"

refuse() { # <name> <VAR> <value> <expected message>: refused by --print-target and by a build, before Configure runs
  local o rc
  o=$(env "$2=$3" bash "$root/tools/openssl/build.sh" --print-target linux-x64 2>&1); rc=$?
  check "$1 (--print-target)" "$([ $rc = 2 ] && grep -qF "$4" <<< "$o" && echo 0 || echo 1)" "exit $rc: $o"
  rm -f "$log".*; o=$(ossl "$tmp/refused" "$2=$3"); rc=$?
  check "$1 (build)" "$([ $rc = 2 ] && grep -qF "$4" <<< "$o" && [ ! -e "$log.args" ] && echo 0 || echo 1)" "exit $rc: $o"
}
refuse "negative_configurePrefixOptionRefused" CFLAGS "-O2 --prefix=/tmp/elsewhere" "'--prefix=/tmp/elsewhere' is an option of OpenSSL's Configure"
refuse "negative_configureDebugOptionRefused" CFLAGS "-d" "'-d' is an option of OpenSSL's Configure"
refuse "negative_configureWithOptionRefused" CPPFLAGS "--with-zlib-include=/x" "'--with-zlib-include=/x' is an option of OpenSSL's Configure"
refuse "negative_configureRpathRefused" LDFLAGS "-rpath /x" "'-rpath' is an option of OpenSSL's Configure"
refuse "negative_percentEscapeRefused" CFLAGS "-DX=%41" "'-DX=%41' is an option of OpenSSL's Configure"
refuse "negative_bareWordRefused" CFLAGS "enable-fips" "'enable-fips' does not start with '-' or '/'"
refuse "negative_loneDashRefused" LDFLAGS "-" "'-' does not start with '-' or '/'"

# -------------------------------------------------------------------- 2. tools/build-ksl-a.sh and tools/build-jni.sh (macOS)
O="$root/build/openssl/macos-arm64"
if [ "$(uname -s)" != Darwin ] || [ ! -f "$O/lib/libcrypto.a" ]; then
  echo "SKIPPED build-ksl-a.sh, build-jni.sh and double-build.sh (they need a macOS host and $O)"
else
  tree="$tmp/tree"; mkdir -p "$tree/kuicksilver-native" "$tree/build/openssl"
  cp -R "$root/tools" "$root/gradle" "$tree/"; cp -R "$root/kuicksilver-native/src" "$tree/kuicksilver-native/"; cp -R "$O" "$tree/build/openssl/"
  wrap="$tmp/cc-wrap"; cclog="$tmp/cc.log"
  printf '#!/bin/sh\n# records each invocation, then compiles\nprintf "%%s\\n" "--" "$@" >> "%s"\nexec clang "$@"\n' "$cclog" > "$wrap"; chmod +x "$wrap"
  invocations() { # <log> <dir>: split the wrapper's log into one file per invocation
    rm -rf "$2"; mkdir -p "$2"; awk -v d="$2" '$0 == "--" { n++; next } { print > (d "/" n) }' "$1"; ls "$2" | wc -l | tr -d ' '
  }
  in_order() { # <invocation file> <word>...: every word present, each after the one before
    local f="$1" prev=0 p; shift
    for w in "$@"; do p=$(pos "$f" "$w"); [ "$p" -gt "$prev" ] || return 1; prev=$p; done
  }

  rm -f "$cclog"
  out=$(CC="$wrap" CPPFLAGS="$F_CPP" CFLAGS="-DKSL_FLAGS_PROBE=1 -MD" bash "$tree/tools/build-ksl-a.sh" macos-arm64 2>&1); rc=$?
  n=$(invocations "$cclog" "$tmp/ksl-inv"); want=$(ls "$tree"/kuicksilver-native/src/c/ksl_*.c | wc -l | tr -d ' ')
  check "build-ksl-a: builds with CC, CPPFLAGS and CFLAGS" "$([ $rc = 0 ] && echo 0 || echo 1)" "$out"
  check "build-ksl-a: CC compiles every source ($want)" "$([ "$n" = "$want" ] && echo 0 || echo 1)" "$n invocations"
  bad=""; for f in "$tmp/ksl-inv"/*; do
    in_order "$f" -std=c11 -fvisibility=hidden -Werror "$F_CPP" -DKSL_FLAGS_PROBE=1 -MD || bad="$bad $(basename "$f")"
  done
  check "build-ksl-a: every compile keeps the project's flags and adds the builder's after them" "$([ -z "$bad" ] && echo 0 || echo 1)" "invocations$bad"
  check "build-ksl-a: CFLAGS take effect (-MD wrote dependency files)" \
    "$([ "$(ls "$tree"/build/ksl/macos-arm64/*.d 2>/dev/null | wc -l | tr -d ' ')" = "$want" ] && echo 0 || echo 1)"
  for v in CPPFLAGS CFLAGS; do
    out=$(env "$v=-include /nonexistent/ksl-flags-probe.h" bash "$tree/tools/build-ksl-a.sh" macos-arm64 2>&1); rc=$?
    check "negative_kslArchiveHonours$v" "$([ $rc != 0 ] && grep -q 'ksl-flags-probe.h' <<< "$out" && echo 0 || echo 1)" "exit $rc"
  done

  rm -f "$cclog"; map="$tmp/jni.map"
  out=$(CC="$wrap" CPPFLAGS="$F_CPP" CFLAGS="-DKSL_FLAGS_PROBE=1" LDFLAGS="-Wl,-map,$map" bash "$tree/tools/build-jni.sh" osx-aarch_64 "$tmp/jni" 2>&1); rc=$?
  n=$(invocations "$cclog" "$tmp/jni-inv")
  check "build-jni: builds with CC, CPPFLAGS, CFLAGS and LDFLAGS" "$([ $rc = 0 ] && [ "$n" = 1 ] && echo 0 || echo 1)" "exit $rc, $n invocations: $out"
  check "build-jni: the project's compile and link flags stay, the builder's come after them" \
    "$(in_order "$tmp/jni-inv/1" -std=c11 -fvisibility=hidden -Werror "$F_CPP" -DKSL_FLAGS_PROBE=1 -dynamiclib "-Wl,-map,$map" && echo 0 || echo 1)"
  check "build-jni: LDFLAGS reach the linker (link map written)" "$([ -s "$map" ] && echo 0 || echo 1)"
  lib=$(ls "$tmp/jni/osx-aarch_64"/libksl_* 2>/dev/null | head -1)
  out=$(bash "$root/tools/check/exports.sh" "$lib" macos 2>&1); rc=$?
  check "build-jni: the library still exports only its entry points" "$([ $rc = 0 ] && echo 0 || echo 1)" "$out"
  out=$(LDFLAGS="-Wl,-ksl-no-such-linker-flag" bash "$tree/tools/build-jni.sh" osx-aarch_64 "$tmp/jni-bad" 2>&1); rc=$?
  check "negative_jniHonoursLdflags" "$([ $rc != 0 ] && grep -q 'ksl-no-such-linker-flag' <<< "$out" && echo 0 || echo 1)" "exit $rc"

  # ------------------------------------------------------------------------------------- 3. tools/check/double-build.sh
  out=$(CC=/nonexistent/cc CPPFLAGS="-include /nonexistent/ksl-flags-probe.h" CFLAGS="-include /nonexistent/ksl-flags-probe.h" \
    LDFLAGS="-Wl,-ksl-no-such-linker-flag" bash "$root/tools/check/double-build.sh" macos-arm64 --skip-openssl 2>&1); rc=$?
  check "negative_doubleBuildIgnoresBuilderFlags" "$([ $rc = 0 ] && grep -q 'byte-identical' <<< "$out" && echo 0 || echo 1)" "exit $rc: $(tail -3 <<< "$out")"
fi

echo "native-flags: $passes passed, $fails failed"
[ "$fails" = 0 ]
