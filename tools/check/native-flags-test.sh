#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Negative controls of the builder's compiler and flags in the native build scripts (docs/guide/building.md):
#   1. tools/openssl/build.sh, against a stub OpenSSL source tree (with stubs of the files the pinned patches change, which
#      apply-patch.pl then patches for real) and a stub make (no compiler runs): CPPFLAGS, CFLAGS and
#      LDFLAGS reach Configure as options after the project's own, in that order, and never through its environment
#      (where Configure would put them in place of the target's flags); configure-target.txt, provenance.txt and
#      --print-target name them; the cache key tells builds with and without them apart; Configure's own options, words
#      that are not flags and %-escapes are refused before anything runs. The Apple targets get llvm-ar as AR and RANLIB
#      (not Xcode's archiver, whose index is not reproducible), and another llvm-ar version is another cache key.
#   2. tools/build-ksl-a.sh and tools/build-jni.sh (macOS, on a copy of the tree): a CC wrapper records every compiler
#      invocation: CC is the compiler, every project flag is still there and the builder's come after them (CPPFLAGS and
#      CFLAGS after -Werror, LDFLAGS after the export list), a flag that cannot compile fails the build, LDFLAGS reach the
#      linker (a link map is written) and the library still exports only its entry points.
#   3. tools/check/double-build.sh (macOS) builds with the project's own compiler, flags and paths: with a CC that does not
#      exist, flags that cannot compile, CCC_OVERRIDE_OPTIONS, CPATH, C_INCLUDE_PATH and SDKROOT (each shown to reach clang)
#      and the other variables of tools/clean-build-env.sh in the environment, it still builds identical copies. The
#      helper itself: every variable it lists is unset, and local-release.sh and verify-release.sh call it before they
#      build (a line-order check; local-release-test.sh runs the release's own case).
# Part 2 also builds the Android library with and without KSL_KEEP_DEBUG=1 when an NDK and build/openssl/android-arm64
# are there. Parts 2 and 3 need a macOS host and build/openssl/macos-arm64; elsewhere they are reported as skipped.
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
# the compression libraries' trees as fetch.sh leaves them: unpacked, with the marker naming the pinned tarball's SHA-256
ctv() { awk -v t="[$1]" -v k="$2" '$0 == t { f = 1; next } /^\[/ { f = 0 } f && $1 == k { v = $3; gsub(/"/, "", v); print v; exit }' "$root/gradle/compression-libs.toml"; }
for lib in zlib brotli; do mkdir -p "$work/src/$lib-$(ctv $lib version)"; ctv $lib sha256 > "$work/src/$lib-$(ctv $lib version)/.ksl-unpacked-sha256"; done
mkdir -p "$work/src/brotli-$(ctv brotli version)/c/enc" "$work/src/brotli-$(ctv brotli version)/c/dec"   # build.sh puts ksl's brotli files there (compression.mk)
echo '#define OPENSSL_VERSION_STR "stub"' > "$src/include/openssl/opensslv.h"
# the files the carried patches (gradle/openssl.toml: patch, patch_2 ... patch_10) change, as stubs they apply to exactly:
# build.sh always runs apply-patch.pl, which wants every context and removed line at the line its hunk names. Each stub
# holds the lines the patches read, in order (a later patch reads the result of the ones before), and filler elsewhere
patches=(); pids=""   # the patch files in order, and the words they add to the target line (build.sh: patch_id)
for n in "" _2 _3 _4 _5 _6 _7 _8 _9 _10; do
  pf=$(sed -n "s/^patch$n = \"\(.*\)\"/\1/p" "$root/gradle/openssl.toml"); [ -z "$pf" ] || patches+=("$root/$pf")
  ps=$(sed -n "s/^patch${n}_sha256 = \"\(.*\)\"/\1/p" "$root/gradle/openssl.toml")
  [ -z "$ps" ] || pids="$pids patch${n//_/-}-sha256=$(printf %s "$ps" | cut -c1-16)"
done
stubbed=$(python3 -I - "$src" ${patches[@]+"${patches[@]}"} <<'PY'
import re, sys
tree, patches = sys.argv[1], sys.argv[2:]
orig, state, need = {}, {}, {}   # per file: original line by index; the current lines ('o', index) or ('n', text); length
N = 1 << 17
for patch in patches:
    lines = open(patch, encoding="latin-1").read().splitlines(keepends=True)
    i = 0
    while i < len(lines) and not lines[i].startswith("--- "):
        i += 1
    while i < len(lines):
        path = lines[i][6:].strip()
        i += 2
        o = orig.setdefault(path, {})
        st = state.setdefault(path, [("o", k) for k in range(N)])
        out, at = [], 0
        while i < len(lines) and lines[i].startswith("@@ "):
            os_, oc, ns, nc = re.match(r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@", lines[i]).groups()
            os_, oc, nc = int(os_), int(oc or 1), int(nc or 1)
            i += 1
            start = os_ if oc == 0 else os_ - 1
            if start > 0 and st[start - 1][0] == "o":   # the line before must exist (an insertion after it)
                need[path] = max(need.get(path, 0), st[start - 1][1] + 1)
            out += st[at:start]
            pos, so, sn = start, 0, 0
            while so < oc or sn < nc:
                tag, text = lines[i][0], lines[i][1:]
                i += 1
                if tag in " -":
                    kind, v = st[pos]
                    if kind == "o":
                        if o.setdefault(v, text) != text: sys.exit(f"{path}: patches disagree on line {v + 1}")
                        need[path] = max(need.get(path, 0), v + 1)
                    elif v != text:
                        sys.exit(f"{path}: a patch reads a line an earlier one wrote otherwise")
                    if tag == " ": out.append(st[pos])
                    pos += 1; so += 1; sn += tag == " "
                else:
                    out.append(("n", text)); sn += 1
            at = pos
        state[path] = out + st[at:]
import os
for path, o in orig.items():
    f = os.path.join(tree, path)
    os.makedirs(os.path.dirname(f), exist_ok=True)
    with open(f, "w", encoding="latin-1") as h:
        h.writelines(o.get(k, f"/* stub line {k + 1} */\n") for k in range(need.get(path, 0)))
print(len(orig))
PY
)
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
ossl() { # <out dir> [VAR=value ...]: tools/openssl/build.sh ${OT:-linux-x64} against the stubs; prints its output
  local out="$1"; shift
  env PATH="$stub:$PATH" KSL_OPENSSL_WORK="$work" KSL_OPENSSL_OUT="$out" KSL_FLAGS_TEST_LOG="$log" "$@" \
    bash "$root/tools/openssl/build.sh" "${OT:-linux-x64}" 2>&1
}
portable() { tr ' ' '\n' | grep -v '/' | grep -v '^$' | tr '\n' ' ' | sed 's/ $//'; }
F_CPP="-DKSL_FLAGS_PROBE_CPP=1"; F_C="-fstack-protector-strong"; F_LD="-Wl,-z,relro"

rm -f "$log".*; out=$(ossl "$tmp/o1"); rc=$?
check "openssl: builds without the builder's flags" "$([ $rc = 0 ] && grep -q '^built linux-x64' <<< "$out" && echo 0 || echo 1)" "$out"
check "openssl: without them Configure ends with the project's flags" "$([ "$(tail -1 "$log.args")" = -fno-common ] && echo 0 || echo 1)" "last: $(tail -1 "$log.args")"
t1=$(portable < "$tmp/o1/linux-x64/configure-target.txt")
check "openssl: configure-target.txt without them is unchanged" "$([ "$t1" = "linux-x86_64 -Os$pids" ] && echo 0 || echo 1)" "$t1"
check "openssl: the carried patches applied to the stub tree" "$([ "${stubbed:-0}" -gt 0 ] || [ ${#patches[@]} = 0 ]; echo $?)" "stubs: ${stubbed:-none}"

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
check "openssl: configure-target.txt names the builder's flags and the word that stands for them" \
  "$(grep -qE "^linux-x86_64 -Os $F_CPP $F_C $F_LD builder-flags-sha256=[0-9a-f]{16}$pids\$" <<< "$t2" && echo 0 || echo 1)" "$t2"
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

zmark="$work/src/zlib-$(ctv zlib version)/.ksl-unpacked-sha256"; cp "$zmark" "$tmp/zmark"
echo 0000 > "$zmark"; rm -f "$log".*; out=$(ossl "$tmp/o5" KSL_OPENSSL_FRESH=1); rc=$?
check "negative_unverifiedZlibTreeRefused" "$([ $rc = 1 ] && grep -q 'is not the verified tree' <<< "$out" && [ ! -e "$log.args" ] && echo 0 || echo 1)" "exit $rc: $out"
cp "$tmp/zmark" "$zmark"

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
refuse "negative_configureNoFeatureRefused" CFLAGS "-O2 -no-ec" "'-no-ec' is an option of OpenSSL's Configure"
refuse "negative_configureNoTls13Refused" CPPFLAGS "-no-tls1_3" "'-no-tls1_3' is an option of OpenSSL's Configure"
refuse "negative_configureDoubleDashSharedRefused" LDFLAGS "--shared" "'--shared' is an option of OpenSSL's Configure"
refuse "negative_configureSharedRefused" LDFLAGS "-shared" "'-shared' is an option of OpenSSL's Configure"
refuse "negative_opensslMacroDefineRefused" CFLAGS "-DOPENSSL_NO_EC" "'-DOPENSSL_NO_EC' sets an OpenSSL configuration macro"
refuse "negative_opensslMacroUndefineRefused" CPPFLAGS "-O2 -UOPENSSL_NO_DEPRECATED_3_0" "'-UOPENSSL_NO_DEPRECATED_3_0' sets an OpenSSL configuration macro"
refuse "negative_configureStaticRefused" LDFLAGS "-static" "'-static' is an option of OpenSSL's Configure"
refuse "negative_includeArgumentStartingWithDRefused" CFLAGS "-include /Data/ksl-probe.h" "'/Data/ksl-probe.h' is an option of OpenSSL's Configure"
refuse "negative_pathStartingWithIRefused" CPPFLAGS "-isystem /Includes/x" "'/Includes/x' is an option of OpenSSL's Configure"
pt=$(CFLAGS="-no-integrated-as" bash "$root/tools/openssl/build.sh" --print-target linux-x64 2>&1); rc=$?
check "openssl: -no-integrated-as is a compiler flag (Configure leaves it alone) and is accepted" "$([ $rc = 0 ] && grep -q -- '-no-integrated-as' <<< "$pt" && echo 0 || echo 1)" "$pt"

# globs: a word with * stays that word, also where it is a path a directory matches
mkdir -p "$tmp/globdir-match"
rm -f "$log".*; out=$(ossl "$tmp/o-glob" CFLAGS="-I $tmp/globdir*"); rc=$?
check "negative_configureFlagNotGlobExpanded" "$([ $rc = 0 ] && [ "$(pos "$log.args" "$tmp/globdir*")" -gt 0 ] && [ "$(pos "$log.args" "$tmp/globdir-match")" = -1 ] && echo 0 || echo 1)" "$out"

# flags that hold a path: the comparison drops such words, the builder-flags word does not
pa=$(CFLAGS="-I/opt/ksl-a" bash "$root/tools/openssl/build.sh" --print-target linux-x64)
pb=$(CFLAGS="-I /opt/ksl-b" bash "$root/tools/openssl/build.sh" --print-target linux-x64)
pc=$(CFLAGS="-I /opt/ksl-c" bash "$root/tools/openssl/build.sh" --print-target linux-x64)
check "negative_pathOnlyFlagsChangePrintTarget" "$([ "$pa" != "$t1" ] && [ "$pb" != "$t1" ] && [ "$pb" != "$pc" ] && [ "$pa" != "$pb" ] && echo 0 || echo 1)" "'$pa' '$pb' '$pc' vs '$t1'"
out=$(ossl "$tmp/o-pa" CFLAGS="-I/opt/ksl-a")
check "openssl: a build with a path-only flag names it in configure-target.txt as --print-target does" \
  "$([ "$(portable < "$tmp/o-pa/linux-x64/configure-target.txt")" = "$pa" ] && echo 0 || echo 1)" "$(cat "$tmp/o-pa/linux-x64/configure-target.txt")"
out=$(ossl "$tmp/o-pd" CFLAGS="-I/opt/ksl-d")
check "negative_pathOnlyFlagsNotReusedFromCache" "$(grep -q '^built linux-x64' <<< "$out" && echo 0 || echo 1)" "$out"

# CC: part of the builder-flags word for macOS; dropped for Android, iOS and mingw, which have their own compiler
m1=$(CC=/opt/ksl/cc-one bash "$root/tools/openssl/build.sh" --print-target macos-arm64)
m2=$(CC=/opt/ksl/cc-two bash "$root/tools/openssl/build.sh" --print-target macos-arm64)
m0=$(bash "$root/tools/openssl/build.sh" --print-target macos-arm64)
check "negative_macosCcChangesPrintTarget" "$([ "$m1" != "$m2" ] && [ "$m1" != "$m0" ] && echo 0 || echo 1)" "'$m1' '$m2' '$m0'"
l1=$(CC=/usr/bin/clang bash "$root/tools/openssl/build.sh" --print-target linux-x64)
lp=$(CC=/opt/rh/devtoolset-10/root/usr/bin/gcc KSL_OPENSSL_BUILD_IMAGE=kuicksilver-openssl-linux-x64 bash "$root/tools/openssl/build.sh" --print-target linux-x64)
lh=$(CC=/opt/rh/devtoolset-10/root/usr/bin/gcc bash "$root/tools/openssl/build.sh" --print-target linux-x64)
lw=$(CC=/opt/rh/devtoolset-10/root/usr/bin/gcc KSL_OPENSSL_BUILD_IMAGE=kuicksilver-openssl-linux-arm64 bash "$root/tools/openssl/build.sh" --print-target linux-x64)
check "negative_linuxCcChangesPrintTarget" "$([ "$l1" != "$t1" ] && echo 0 || echo 1)" "'$l1' vs '$t1'"
check "openssl: the image's own compiler, inside the image (build-docker.sh's marker), is not a builder's CC" "$([ "$lp" = "$t1" ] && echo 0 || echo 1)" "'$lp' vs '$t1'"
check "negative_devtoolsetCcOnBareHostCounts" "$([ "$lh" != "$t1" ] && echo 0 || echo 1)" "'$lh' vs '$t1'"
check "negative_devtoolsetCcWithAnotherImagesMarkerCounts" "$([ "$lw" != "$t1" ] && echo 0 || echo 1)" "'$lw' vs '$t1'"
check "openssl: build-docker.sh sets the marker build.sh expects" \
  "$(grep -q -- '-e KSL_OPENSSL_BUILD_IMAGE="$img"' "$root/tools/openssl/build-docker.sh" && grep -q '^img="kuicksilver-openssl-$df"' "$root/tools/openssl/build-docker.sh" && echo 0 || echo 1)"
dcc=$(sed -n 's/^  linux-x64) .* cc=\([^ ;]*\) ;;.*/\1/p' "$root/tools/openssl/build-docker.sh"); bcc=$(sed -n 's/^project_linux_cc=//p' "$root/tools/openssl/build.sh")
check "openssl: build.sh and build-docker.sh name the same Linux compiler" "$([ -n "$dcc" ] && [ "$dcc" = "$bcc" ] && echo 0 || echo 1)" "'$dcc' vs '$bcc'"
a1=$(CC=/opt/ksl/cc-one bash "$root/tools/openssl/build.sh" --print-target android-arm64)
a0=$(bash "$root/tools/openssl/build.sh" --print-target android-arm64)
check "openssl: CC does not change Android's configure line" "$([ "$a1" = "$a0" ] && echo 0 || echo 1)" "'$a1' vs '$a0'"
ndk="$tmp/fake-ndk"; mkdir -p "$ndk/toolchains/llvm/prebuilt/host/bin"
rm -f "$log".*; out=$(OT=android-arm64 ossl "$tmp/o-android" ANDROID_NDK_ROOT="$ndk" CC=/opt/ksl/not-the-ndk-clang); rc=$?
check "negative_androidIgnoresBuilderCc" "$([ -s "$log.args" ] && ! grep -q '^CC=' "$log.args" && echo 0 || echo 1)" "exit $rc: $(grep '^CC=' "$log.args" 2>/dev/null) $out"
# the Apple targets archive with llvm-ar, never Xcode's ar/ranlib (whose index leaves uninitialised padding): Configure gets it
# in its environment as AR and RANLIB, and the tool's version is part of the cache key (another llvm-ar, another build)
far="$tmp/fake-llvm-ar"; mkdir -p "$far"
fake_ar() { printf '#!/bin/sh\necho "LLVM (http://llvm.org/):"\necho "  LLVM version %s"\n' "$1" > "$far/llvm-ar"; chmod +x "$far/llvm-ar"; }
fake_ar 1.0.0-ksl-a
rm -f "$log".*; out=$(OT=macos-arm64 ossl "$tmp/o-ar1" LLVM_AR="$far/llvm-ar"); rc=$?
check "openssl: an Apple target archives with llvm-ar (AR and RANLIB in Configure's environment)" \
  "$([ $rc = 0 ] && grep -qxF "AR=$far/llvm-ar" "$log.env" && grep -qxF "RANLIB=$far/llvm-ar s" "$log.env" && echo 0 || echo 1)" \
  "exit $rc: $(grep -E '^(AR|RANLIB)=' "$log.env" 2>/dev/null) $out"
out=$(OT=macos-arm64 ossl "$tmp/o-ar2" LLVM_AR="$far/llvm-ar")
check "openssl: the same llvm-ar again takes the cache" "$(grep -q '^cache hit' <<< "$out" && echo 0 || echo 1)" "$out"
fake_ar 1.0.0-ksl-b; out=$(OT=macos-arm64 ossl "$tmp/o-ar3" LLVM_AR="$far/llvm-ar")
check "negative_otherLlvmArVersionNotReusedFromCache" "$(grep -q '^built macos-arm64' <<< "$out" && echo 0 || echo 1)" "$out"
rm -f "$log".*; out=$(OT=ios-arm64 ossl "$tmp/o-ar4" LLVM_AR="$far/llvm-ar"); rc=$?
check "openssl: ... and so does iOS" "$([ $rc = 0 ] && grep -qxF "AR=$far/llvm-ar" "$log.env" && echo 0 || echo 1)" "exit $rc: $out"

# ------------------------------------------------------------------------------------------ tools/clean-build-env.sh
# the variables the release, the double build and verify-release's rebuild clear: every one listed is unset, the list has
# those a review proved to reach a build, and each of the three sources the helper before it builds anything
out=$( . "$root/tools/clean-build-env.sh"
  for v in "${ksl_build_env_vars[@]}"; do export "$v=probe"; done
  ksl_clean_build_env
  for v in "${ksl_build_env_vars[@]}"; do [ -z "${!v+x}" ] || echo "still set: $v"; done
  for v in CC CPPFLAGS CFLAGS LDFLAGS OPT CCC_OVERRIDE_OPTIONS CPATH C_INCLUDE_PATH CPLUS_INCLUDE_PATH LIBRARY_PATH AR RANLIB \
           SDKROOT MAKEFLAGS OPENSSL_LOCAL_CONFIG_DIR __CNF_CFLAGS KSL_OPENSSL_PIN KSL_KEEP_DEBUG CROSS_SYSROOT PERL5OPT \
           PERL5LIB PERLLIB TOOLCHAINS LD_RUN_PATH DYLD_INSERT_LIBRARIES LD_PRELOAD KSL_OPENSSL_BUILD_IMAGE; do
    printf '%s\n' "${ksl_build_env_vars[@]}" | grep -qx "$v" || echo "not in the list: $v"
  done )
check "negative_cleanBuildEnvLeavesNothingSet" "$([ -z "$out" ] && echo 0 || echo 1)" "$out"
# the hosted jobs' guard: a value the workflow sets on purpose passes, anything else is named
gfake="$tmp/guard-ndk"; mkdir -p "$gfake/toolchains/llvm/prebuilt/host/bin"; touch "$gfake"/toolchains/llvm/prebuilt/host/bin/llvm-{nm,objcopy,objdump,readelf,ar}
g() { ( . "$root/tools/clean-build-env.sh"; for v in "${ksl_build_env_vars[@]}"; do unset "$v"; done; export "$@"; ksl_build_env_guard ); }
out=$(g ANDROID_NDK_ROOT="$gfake" LLVM_NM="$gfake/toolchains/llvm/prebuilt/host/bin/llvm-nm" LLVM_OBJCOPY="$gfake/toolchains/llvm/prebuilt/host/bin/llvm-objcopy" LLVM_AR="$gfake/toolchains/llvm/prebuilt/host/bin/llvm-ar")
check "guard: the pinned NDK's LLVM tools (set by the setup action) pass" "$([ -z "$out" ] && echo 0 || echo 1)" "$out"
out=$(g ANDROID_NDK_ROOT="$gfake" LLVM_OBJCOPY=/opt/other/llvm-objcopy)
check "negative_guardNamesForeignLlvmTool" "$([ "$out" = LLVM_OBJCOPY ] && echo 0 || echo 1)" "$out"
out=$(g CFLAGS=-O0 CCC_OVERRIDE_OPTIONS=+-O0 SDKROOT=/nonexistent/sdk)
check "negative_guardNamesBuildVariables" "$([ "$out" = "CFLAGS CCC_OVERRIDE_OPTIONS SDKROOT" ] && echo 0 || echo 1)" "$out"
if sdk=$(xcrun --sdk macosx --show-sdk-path 2>/dev/null) && [ -n "$sdk" ]; then
  out=$(g SDKROOT="$sdk")
  check "guard: SDKROOT equal to the selected Xcode's macOS SDK passes" "$([ -z "$out" ] && echo 0 || echo 1)" "$out"
fi
# Perl runs OpenSSL's build: PERL5OPT reaches it (control), and a release-like build has it unset (the helper, then a build)
out=$(ossl "$tmp/o-perl" KSL_OPENSSL_FRESH=1 PERL5OPT=-MKslNoSuchModule); rc=$?
# with carried patches the first Perl to run is shasum (a Perl script on macOS) checking their hashes, whose error build.sh
# reports as an unreadable file; without, Configure's own
check "control: PERL5OPT reaches the OpenSSL build (it fails with it)" \
  "$([ $rc != 0 ] && grep -qE 'KslNoSuchModule|has SHA-256 <unreadable>' <<< "$out" && echo 0 || echo 1)" "exit $rc: $out"
out=$( export PERL5OPT=-MKslNoSuchModule PERL5LIB=/nonexistent CROSS_SYSROOT=/nonexistent; . "$root/tools/clean-build-env.sh"; ksl_clean_build_env; ossl "$tmp/o-perl-clean" KSL_OPENSSL_FRESH=1); rc=$?
check "negative_cleanBuildEnvStopsPerl5opt" "$([ $rc = 0 ] && grep -q '^built linux-x64' <<< "$out" && echo 0 || echo 1)" "exit $rc: $out"
first_line() { grep -n -m1 -E "$2" "$1" | cut -d: -f1; }
c=$(first_line "$root/tools/release/local-release.sh" 'ksl_clean_build_env'); b=$(first_line "$root/tools/release/local-release.sh" '^step ')
check "local-release.sh clears the build environment before its first step" "$([ -n "$c" ] && [ -n "$b" ] && [ "$c" -lt "$b" ] && echo 0 || echo 1)" "line $c vs $b"
c=$(first_line "$root/tools/verify/verify-release.sh" 'ksl_clean_build_env'); b=$(first_line "$root/tools/verify/verify-release.sh" 'tools/openssl/build.sh"')
check "verify-release.sh clears the build environment before it rebuilds" "$([ -n "$c" ] && [ -n "$b" ] && [ "$c" -lt "$b" ] && echo 0 || echo 1)" "line $c vs $b"

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

  out=$(CC="clang*" bash "$tree/tools/build-ksl-a.sh" macos-arm64 2>&1); rc=$?
  check "negative_kslArchiveCcGlobRefused" "$([ $rc = 2 ] && grep -q 'glob character' <<< "$out" && echo 0 || echo 1)" "exit $rc: $out"
  out=$(CC="cl[a]ng" bash "$tree/tools/build-jni.sh" osx-aarch_64 "$tmp/jni-glob" 2>&1); rc=$?
  check "negative_jniCcGlobRefused" "$([ $rc = 2 ] && grep -q 'glob character' <<< "$out" && echo 0 || echo 1)" "exit $rc: $out"
  rm -f "$cclog"; mkdir -p "$tmp/globinc-match"
  out=$(CC="$wrap" CFLAGS="-I $tmp/globinc*" bash "$tree/tools/build-ksl-a.sh" macos-arm64 2>&1); rc=$?
  invocations "$cclog" "$tmp/glob-inv" >/dev/null
  check "negative_kslArchiveFlagNotGlobExpanded" "$([ $rc = 0 ] && [ "$(pos "$tmp/glob-inv/1" "$tmp/globinc*")" -gt 0 ] && [ "$(pos "$tmp/glob-inv/1" "$tmp/globinc-match")" = -1 ] && echo 0 || echo 1)" "exit $rc"

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

  # KSL_KEEP_DEBUG=1 (local builds): the Android library keeps its symbol table and, with -g, its debug information
  readelf=$( (ls -d "${ANDROID_NDK_ROOT:-/nonexistent}"/toolchains/llvm/prebuilt/*/bin/llvm-readelf "$HOME"/Library/Android/sdk/ndk/*/toolchains/llvm/prebuilt/*/bin/llvm-readelf 2>/dev/null || true) | tail -1)
  if [ -n "$readelf" ] && [ -f "$root/build/openssl/android-arm64/lib/libcrypto.a" ]; then
    cp -R "$root/build/openssl/android-arm64" "$tree/build/openssl/"
    out=$(KSL_KEEP_DEBUG=1 CFLAGS=-g bash "$tree/tools/build-android-so.sh" arm64-v8a "$tmp/android-keep" 2>&1); rc=$?
    check "KSL_KEEP_DEBUG=1: the Android library keeps .symtab and .debug_info" \
      "$([ $rc = 0 ] && [ "$("$readelf" -S "$tmp/android-keep/arm64-v8a/libksl.so" | grep -cE '\.debug_info|\.symtab')" = 2 ] && echo 0 || echo 1)" "exit $rc"
    out=$(CFLAGS=-g bash "$tree/tools/build-android-so.sh" arm64-v8a "$tmp/android-strip" 2>&1); rc=$?
    check "negative_androidStrippedWithoutKeepDebug" \
      "$([ $rc = 0 ] && [ "$("$readelf" -S "$tmp/android-strip/arm64-v8a/libksl.so" | grep -cE '\.debug_info|\.symtab')" = 0 ] && echo 0 || echo 1)" "exit $rc"
  else
    echo "SKIPPED KSL_KEEP_DEBUG on Android (no NDK llvm-readelf or no build/openssl/android-arm64)"
  fi

  # ------------------------------------------------------------------------------------- 3. tools/check/double-build.sh
  # the environment a builder may have: each of these reaches clang on its own (the controls show it), the double build
  # must ignore them all
  probe="$tmp/probe-include"; mkdir -p "$probe"; printf '#error ksl-env-probe\n' > "$probe/stdint.h"
  for e in "CCC_OVERRIDE_OPTIONS=+-include/nonexistent/ksl-env-probe.h" "CPATH=$probe" "C_INCLUDE_PATH=$probe" "SDKROOT=/nonexistent/sdk"; do
    out=$(env "$e" bash "$tree/tools/build-ksl-a.sh" macos-arm64 2>&1); rc=$?
    check "control: ${e%%=*} reaches clang (a build-ksl-a.sh build fails because of it)" \
      "$([ $rc != 0 ] && grep -qE 'ksl-env-probe|/nonexistent/sdk' <<< "$out" && echo 0 || echo 1)" "exit $rc"
  done
  out=$(CC=/nonexistent/cc CPPFLAGS="-include /nonexistent/ksl-flags-probe.h" CFLAGS="-include /nonexistent/ksl-flags-probe.h" \
    LDFLAGS="-Wl,-ksl-no-such-linker-flag" CCC_OVERRIDE_OPTIONS="+-include/nonexistent/ksl-env-probe.h" CPATH="$probe" \
    C_INCLUDE_PATH="$probe" SDKROOT=/nonexistent/sdk LIBRARY_PATH=/nonexistent AR=/nonexistent/ar RANLIB=/nonexistent/ranlib \
    OPT=-O0 MAKEFLAGS=-e KSL_OPENSSL_OUT=/nonexistent KSL_OPENSSL_PREFIXED=/nonexistent KSL_KEEP_DEBUG=1 \
    LD_RUN_PATH=/nonexistent/rpath TOOLCHAINS=com.ksl.nonexistent PERL5OPT=-MKslNoSuchModule PERL5LIB=/nonexistent \
    CROSS_SYSROOT=/nonexistent \
    bash "$root/tools/check/double-build.sh" macos-arm64 --skip-openssl 2>&1); rc=$?
  check "negative_doubleBuildIgnoresBuilderFlags" "$([ $rc = 0 ] && grep -q 'byte-identical' <<< "$out" && echo 0 || echo 1)" "exit $rc: $(tail -3 <<< "$out")"
fi

echo "native-flags: $passes passed, $fails failed"
[ "$fails" = 0 ]
