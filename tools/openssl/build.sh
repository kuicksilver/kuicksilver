#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Build static OpenSSL for one target with the reduced configuration in tools/openssl/configure-flags.txt (plus -fvisibility=hidden -fno-common).
# Usage: build.sh <target>               build (or take from the cache) into build/openssl/<target>
#        build.sh --print-target <target>   print the configure line of <target> without the machine's paths (what
#                                           configure-target.txt must say once path tokens are dropped; openssl.gradle.kts)
#   targets: macos-arm64 ios-arm64 ios-sim-arm64 android-arm64 android-x86_64 android-arm
#            linux-x64 linux-arm64 mingw-x64 linux-x64-kn linux-arm64-kn
# Env: KSL_OPENSSL_PIN=<pin profile> (default gradle/openssl.toml; gradle/openssl-next.toml builds the 4.x of the CI job openssl-next),
#      ANDROID_NDK_ROOT (android), KONAN_SYSROOT (-kn targets), CC override, OPT (default -Os),
#      KSL_OPENSSL_FRESH=1  never take the cache: configure and compile from the source fetch.sh just verified (release),
#      CPPFLAGS, CFLAGS, LDFLAGS  the builder's flags, added after the project's (below)
# The builder's CPPFLAGS, CFLAGS and LDFLAGS: OpenSSL's Configure would read them from the environment and use them in
# place of the target's own flags, so they are taken out of its environment and passed as Configure options after the
# project's, which adds them (a later flag wins where two conflict). Each must be one word that starts with '-' (or '/', the
# argument of the flag before it) and is not one of Configure's own options (-d -v -w -t -rpath -R -framework, --prefix
# and the other --options); the script refuses anything else. They are part of the cache key, of configure-target.txt and
# of --print-target, so -Pkuicksilver.openssl.prebuilt reuses a build only with the flags it was made with. CXXFLAGS and
# LDLIBS are not used (no C++, no program is linked). A release and the reproducibility checks build with them unset
# (docs/guide/building.md).
# Next to the archives: configure-flags.txt, configure-target.txt and provenance.txt (the pinned tarball SHA-256, the target
# line and the SHA-256 of libcrypto.a and libssl.a), which -Pkuicksilver.openssl.prebuilt compares before reusing a build.
# The carried patch (ADR-0019): when the pin profile names one (patch, patch_sha256), the file must have that SHA-256, and
# tools/openssl/apply-patch.pl applies it, exactly, to the copy of the verified tree the build runs in; its hash is part of
# the cache key, of the target line (a token patch-sha256=<first 16 hex>) and of provenance.txt (patch-sha256 <hash>).
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
print_only=0; [ "${1:-}" = "--print-target" ] && { print_only=1; shift; }
target="${1:?target}"
root="$here/../.."; out="${KSL_OPENSSL_WORK:-$root/build/openssl-work}"
# KSL_OPENSSL_PIN: another pin profile, a path from the repository root (gradle/openssl-next.toml: the CI job openssl-next)
pin="${KSL_OPENSSL_PIN:-gradle/openssl.toml}"; case "$pin" in /*) toml="$pin" ;; *) toml="$root/$pin" ;; esac
[ -f "$toml" ] || { echo "no pin profile $toml" >&2; exit 1; }
version=$(sed -n 's/^version = "\(.*\)"/\1/p' "$toml")
src="$out/src/openssl-$version"
patch_file=$(sed -n 's/^patch = "\(.*\)"/\1/p' "$toml"); patch_sha=$(sed -n 's/^patch_sha256 = "\(.*\)"/\1/p' "$toml")
case "${patch_file:+f}${patch_sha:+s}" in ""|fs) ;; *) echo "$toml: patch and patch_sha256 go together" >&2; exit 1 ;; esac
patch_id="${patch_sha:+patch-sha256=$(printf %s "$patch_sha" | cut -c1-16)}"
if [ -n "$patch_file" ] && [ "$print_only" != 1 ]; then
  actual=$(shasum -a 256 < "$root/$patch_file" 2>/dev/null | cut -d' ' -f1) || actual=""
  [ "$actual" = "$patch_sha" ] || { echo "FAILED: $patch_file has SHA-256 ${actual:-<unreadable>}, $toml pins $patch_sha" >&2; exit 1; }
fi
[ "$print_only" = 1 ] || [ -d "$src" ] || { echo "run fetch.sh first" >&2; exit 1; }
OPT="${OPT:--Os}"
# the builder's flags, word by word into an array (never glob-expanded), refused where Configure would read a word as
# something other than a compiler flag: its own options, -no-<feature> (Configure rewrites it to no-<feature>, which would
# turn a feature off), -shared and --shared (rewritten to enable-shared), -static (it disables static, pic and threads),
# a word starting /D or /I (read as a define or an include directory, so the argument of `-include /Data/x.h` would
# become one), a word that is no flag, and %xx (decoded); also -D or -U of an OPENSSL_* macro, which would build the
# libraries with a configuration other than the one their installed opensslconf.h and configuration.h declare
user_args=(); read -r -a user_words <<< "${CPPFLAGS:-} ${CFLAGS:-} ${LDFLAGS:-}"
for w in ${user_words[@]+"${user_words[@]}"}; do
  case "$w" in
    -no-integrated-as) user_args+=("$w") ;;
    -DOPENSSL_*|-UOPENSSL_*|/DOPENSSL_*|/UOPENSSL_*)
      echo "CPPFLAGS/CFLAGS/LDFLAGS: '$w' sets an OpenSSL configuration macro, which the installed headers would not match; refused (configure-flags.txt decides them)" >&2; exit 2 ;;
    -d|-v|-w|-t|-rpath|-R|-framework|-no-*|-shared|--shared|-static|/D*|/I*|--prefix=*|--api=*|--libdir=*|--openssldir=*|--with-*|--fips-key=*|--banner=*|--cross-compile-prefix=*|--config=*|--strict-warnings|--debug|--release|*%*)
      echo "CPPFLAGS/CFLAGS/LDFLAGS: '$w' is an option of OpenSSL's Configure, not a compiler flag; refused" >&2; exit 2 ;;
    -?*|/*) user_args+=("$w") ;;
    *) echo "CPPFLAGS/CFLAGS/LDFLAGS: '$w' does not start with '-' or '/'; refused (Configure would take it for a target or an option)" >&2; exit 2 ;;
  esac
done
user_flags="${user_args[*]+"${user_args[*]}"}"
# CC: used for macOS and Linux (passed to Configure). For Linux the project's own compiler is the image's devtoolset gcc,
# which tools/openssl/build-docker.sh sets (the same path; native-flags-test.sh checks the two agree) together with the
# marker KSL_OPENSSL_BUILD_IMAGE: only inside our image is that path not a builder's choice. On a bare Linux host the
# same path (another devtoolset) counts like any other CC. The Kotlin/Native targets set their compiler below; Android, iOS and mingw use their toolchain's own
# (the NDK's clang, Xcode's, the image's mingw gcc), so a CC from the builder is dropped there.
project_linux_cc=/opt/rh/devtoolset-10/root/usr/bin/gcc
case "$target" in
  macos-*) user_cc="${CC:-}" ;;
  linux-x64|linux-arm64) user_cc="${CC:-}"
    [ "$user_cc" != "$project_linux_cc" ] || [ "${KSL_OPENSSL_BUILD_IMAGE:-}" != "kuicksilver-openssl-$target" ] || user_cc="" ;;
  android-*|ios-*|mingw-x64) user_cc=""; unset CC ;;
  *) user_cc="" ;;
esac
# One word that stands for all of the builder's flags and CC, paths included: configure-target.txt and --print-target name
# it, so a build made with other flags or another CC is never reused (the comparison drops words that hold a path).
user_id=""
if [ ${#user_args[@]} -gt 0 ] || [ -n "$user_cc" ]; then
  user_id="builder-flags-sha256=$( { printf 'CC=%s\0' "$user_cc"; printf '%s\0' ${user_args[@]+"${user_args[@]}"}; } | shasum -a 256 | cut -c1-16)"
fi
# Configure would use these instead of the target's flags; __CNF_*, OPENSSL_LOCAL_CONFIG_DIR, BUILDFILE and CROSS_COMPILE
# would change its configuration as well, unrecorded
unset CPPFLAGS CFLAGS CXXFLAGS LDFLAGS LDLIBS __CNF_CPPDEFINES __CNF_CPPINCLUDES __CNF_CPPFLAGS __CNF_CFLAGS __CNF_CXXFLAGS \
  __CNF_LDFLAGS __CNF_LDLIBS OPENSSL_LOCAL_CONFIG_DIR BUILDFILE CROSS_COMPILE
export SOURCE_DATE_EPOCH=1759363200
export ZERO_AR_DATE=1   # Apple ar ignores SOURCE_DATE_EPOCH; this zeroes archive member timestamps
JOBS="${JOBS:-4}"       # keep the host responsive (owner request)

case "$target" in
  macos-arm64)   cfg=darwin64-arm64-cc;  extra="-mmacosx-version-min=11.0" ;;
  macos-x64)     cfg=darwin64-x86_64-cc; extra="-mmacosx-version-min=11.0" ;;
  ios-arm64)     cfg=ios64-xcrun;        extra="-mios-version-min=15.0" ;;
  ios-sim-arm64) cfg=iossimulator-arm64-xcrun; extra="-mios-simulator-version-min=15.0" ;;
  android-arm64|android-x86_64|android-arm)
    # the NDK pinned in gradle/toolchains.toml when installed, else the newest one (CI sets ANDROID_NDK_ROOT to the pinned NDK)
    pin=$(sed -n 's/^ndk = "\(.*\)".*/\1/p' "$root/gradle/toolchains.toml" 2>/dev/null || true)
    export ANDROID_NDK_ROOT="${ANDROID_NDK_ROOT:-$( (ls -d "$HOME"/Library/Android/sdk/ndk/"${pin:-none}" "$HOME"/Android/Sdk/ndk/"${pin:-none}" 2>/dev/null || ls -d "$HOME"/Library/Android/sdk/ndk/* "$HOME"/Android/Sdk/ndk/* 2>/dev/null || true) | sort -V | tail -1)}"; [ -d "$ANDROID_NDK_ROOT" ] || [ "$print_only" = 1 ] || { echo "set ANDROID_NDK_ROOT" >&2; exit 2; }
    cfg=$target   # the OpenSSL Configure names; android-arm is armv7-a (NDK triple armv7a-linux-androideabi, its default softfp ABI + NEON)
    tc="$ANDROID_NDK_ROOT/toolchains/llvm/prebuilt/$(ls "$ANDROID_NDK_ROOT/toolchains/llvm/prebuilt" 2>/dev/null || true)"
    export PATH="$tc/bin:$PATH"
    extra="-D__ANDROID_API__=24 -Wl,-z,max-page-size=16384 -Wl,-z,common-page-size=16384" ;;
  linux-x64)     cfg=linux-x86_64; extra="" ;;
  linux-arm64)   cfg=linux-aarch64; extra="" ;;
  mingw-x64)     cfg=mingw64; extra="--cross-compile-prefix=x86_64-w64-mingw32-" ;;
  linux-x64-kn|linux-arm64-kn)
    # Kotlin/Native toolchain: konan clang + the gcc-8.3.0/glibc sysroot K/N links against.
    kdeps="${KONAN_DEPS:-$HOME/.konan/dependencies}"
    # konan.properties: macOS hosts use the "essentials" LLVM, Linux x64 hosts the "dev" one (llvm-21-x86_64-linux-dev-*)
    llvm=$( (ls -d "$kdeps"/llvm-21-*-essentials-* "$kdeps"/llvm-21-*-dev-* 2>/dev/null || true) | head -1)
    [ -n "$llvm" ] || [ "$print_only" = 1 ] || { echo "no Kotlin/Native LLVM in $kdeps (run tools/ci/konan-bootstrap.sh)" >&2; exit 2; }
    if [ "$target" = linux-x64-kn ]; then triple=x86_64-unknown-linux-gnu; cfg=linux-x86_64; else triple=aarch64-unknown-linux-gnu; cfg=linux-aarch64; fi
    tc=$( (ls -d "$kdeps"/$triple-gcc-8.3.0-glibc-* 2>/dev/null || true) | head -1)
    export CC="$llvm/bin/clang"
    export AR="$llvm/bin/llvm-ar" RANLIB="$llvm/bin/llvm-ar s"
    extra="--target=$triple --sysroot=$tc/$triple/sysroot --gcc-toolchain=$tc -U_FORTIFY_SOURCE -fuse-ld=lld" ;;
  *) echo "unknown target $target" >&2; exit 2 ;;
esac

# the configure line without path tokens: what must match between the machine that built an archive and the one reusing it
portable() { tr ' ' '\n' | grep -v '/' | grep -v '^$' | tr '\n' ' ' | sed 's/ $//'; }
if [ "$print_only" = 1 ]; then echo "$cfg $OPT $extra $user_flags $user_id $patch_id" | portable; echo; exit 0; fi
flags=$(grep -v '^#' "$here/configure-flags.txt" | tr '\n' ' ')
# Cache key: the compiler that will actually run (Configure resolves it per target), this script, the flags, the source.
case "$cfg" in android-*) realcc=$(command -v clang) ;; ios*) realcc=$(xcrun -f clang 2>/dev/null || echo clang) ;; mingw64) realcc=$(command -v x86_64-w64-mingw32-gcc || echo unknown) ;; *) realcc=${CC:-cc} ;; esac
ccid="$realcc|$("$realcc" --version 2>/dev/null | head -1 || echo unknown)|$(shasum -a 256 < "$0" | cut -c1-16)"
key=$(printf '%s|%s|%s|%s|%s|%s%s' "$(sed -n 's/^sha256 = "\(.*\)"/\1/p' "$toml")" "$(shasum -a 256 < "$here/configure-flags.txt" | cut -c1-16)" "$target" "$ccid" "$OPT" "$extra" "${user_id:+|$user_id}${patch_id:+|$patch_id}" | shasum -a 256 | cut -c1-16)
cache="$out/cache/$key"
dest="${KSL_OPENSSL_OUT:-$root/build/openssl}/$target"
provenance() { # <dir>: what was built from what, checked by -Pkuicksilver.openssl.prebuilt (openssl.gradle.kts)
  { echo "tarball-sha256 $(sed -n 's/^sha256 = "\(.*\)"/\1/p' "$toml")"; echo "target $(portable < "$1/configure-target.txt")"
    for a in libcrypto.a libssl.a; do echo "$a $(shasum -a 256 < "$1/lib/$a" | cut -d' ' -f1)"; done
    [ -z "$patch_sha" ] || echo "patch-sha256 $patch_sha"; } > "$1/provenance.txt"
}
if [ -d "$cache/lib" ] && [ "${KSL_OPENSSL_FRESH:-0}" != 1 ]; then
  rm -rf "$dest"; mkdir -p "$(dirname "$dest")"; cp -R "$cache" "$dest"; [ -f "$dest/provenance.txt" ] || provenance "$dest"
  echo "cache hit $key -> $dest"; exit 0
fi

work="$out/build/$target"
rm -rf "$work" "$cache"; mkdir -p "$work"; cp -R "$src/." "$work/"
cd "$work"
[ -z "$patch_file" ] || perl "$here/apply-patch.pl" "$root/$patch_file" "$work" >"$out/build/$target.patch.log" 2>&1 \
  || { cat "$out/build/$target.patch.log" >&2; echo "FAILED: $patch_file does not apply to OpenSSL $version" >&2; exit 1; }
# shellcheck disable=SC2086
./Configure "$cfg" $flags --prefix=/nonexistent --openssldir=/nonexistent $OPT -ffunction-sections -fdata-sections -fvisibility=hidden -fno-common $extra ${user_args[@]+"${user_args[@]}"} ${CC:+CC=$CC} >"$out/build/$target.configure.log" 2>&1
# The "compiler:" line of OpenSSL_version(OPENSSL_CFLAGS) is compiled into libcrypto.a (crypto/buildinf.h, from the
# compiler command and its flags): kept without the tokens that hold a path (the compiler's, a sysroot, a toolchain), so
# no directory of the machine that built an archive ends up in it. make leaves the rewritten header alone, as it is newer
# than what it is generated from.
# The format is util/mkbuildinf.pl's of OpenSSL 3.5 and 4.1 (gradle/openssl.toml, gradle/openssl-next.toml): a PLATFORM
# define and compiler_flags[] as one character literal per character, the flags' backslashes doubled before the split
# (undone here, so a rewritten header reads back to the same line); any other layout stops the build.
make crypto/buildinf.h >"$out/build/$target.make.log" 2>&1
KSL_V="$version" perl -0777 -ne '
  my $fmt = "crypto/buildinf.h of OpenSSL $ENV{KSL_V} is not in the layout tools/openssl/build.sh rewrites";
  my ($plat) = /#define PLATFORM "platform: (.*?)"/ or die "$fmt: no PLATFORM define\n";
  my ($body) = /compiler_flags\[\] = \{(.*?)\};/s or die "$fmt: no compiler_flags[] array\n";
  my $s = join "", map { (my $c = $_) =~ s/\\(.)/$1/; $c } ($body =~ /\x27((?:\\.|[^\\\x27])*)\x27,/g);
  $s =~ s/\\\\/\\/g;   # mkbuildinf.pl doubled every backslash of the flags
  $s =~ s/^compiler: // or die "$fmt: compiler_flags[] does not start with compiler:\n";
  my @t = grep { !m{/} } split /\s+/, $s; unshift @t, "cc" if !@t || $t[0] =~ /^-/;
  print join(" ", @t), "\n", $plat, "\n";' crypto/buildinf.h > "$out/build/$target.buildinf.txt"
rm -f crypto/buildinf.h   # OpenSSL 4 generates it read-only (util/file-from-stdout.pl); rewritten below
perl util/mkbuildinf.pl "$(sed -n 1p "$out/build/$target.buildinf.txt")" "$(sed -n 2p "$out/build/$target.buildinf.txt")" > crypto/buildinf.h
make -j"$JOBS" build_libs >>"$out/build/$target.make.log" 2>&1
mkdir -p "$cache/lib" "$cache/include"
cp libcrypto.a libssl.a "$cache/lib/"
cp -R include/openssl "$cache/include/"
cp "$here/configure-flags.txt" "$cache/configure-flags.txt"; echo "$cfg $OPT $extra${user_flags:+ $user_flags}${user_id:+ $user_id}${patch_id:+ $patch_id}" > "$cache/configure-target.txt"; provenance "$cache"
rm -rf "$dest"; mkdir -p "$(dirname "$dest")"; cp -R "$cache" "$dest"
echo "built $target -> $dest (cache $key)"
