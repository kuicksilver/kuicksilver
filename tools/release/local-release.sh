#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Release to Maven Central from the owner's Mac (docs/release.md, "Every release"): everything .github/workflows/release.yml
# and the JNI jobs of build.yml do, with no GitHub runner. One Gradle publish invocation, so one Central deployment, which
# stops at VALIDATED (automaticRelease = false): the owner presses Publish in the portal. This script never tags or pushes.
#
#   1. refuses unless: the version is X.Y.Z[-alpha|beta|rcN] (no -SNAPSHOT); HEAD is main (or the commit named by
#      --release-commit, contained in main); the tree is clean; build/ci/gate/<HEAD>.stamp from tools/ci/local-matrix.sh
#      says the full matrix (Android, Docker, interop, Windows) passed on this exact commit; CHANGELOG.md has the version;
#      the NDK and Xcode of gradle/toolchains.toml are installed; the portal token and a signing key are configured.
#   2. OpenSSL: fetch and verify the pinned tarball; rebuild all twelve targets from it, never from build/openssl or the build
#      cache (KSL_OPENSSL_FRESH=1): linux-x64, linux-arm64 and mingw-x64 in Docker (one container at a time, under nice;
#      linux-x64 and mingw run emulated on Apple Silicon), the macOS, iOS, Android and Kotlin/Native Linux ones on the host;
#      no-sslkeylog in each; the prefixed Kotlin/Native archives are made again from them.
#   3. The five JVM libraries, each into build/release/jni-artifacts/jni-<classifier> (the layout of the CI artifacts):
#      osx-aarch_64, osx-x86_64 (cross-built with clang -arch x86_64), linux-x86_64, linux-aarch_64 (manylinux2014),
#      windows-x86_64 (mingw-w64, tools/ci/jni-windows.sh). Checks per library: architecture, export whitelist, the shared
#      libraries it imports, the glibc floor 2.17 (Linux), the pinned OpenSSL version string inside, its manifest.sha256.
#   4. tools/ci/collect-jni.sh, the kuicksilver-native jar, --check-jar (all five present), the jar's libraries equal to the
#      collected ones, its manifest naming the pinned OpenSSL and this commit.
#   5. publishToMavenLocal into build/release/m2 (never ~/.m2), file count and size against the Central limits; the published
#      AAR's three libksl.so and every Kotlin/Native klib's static archives checked as the JVM libraries are (pinned OpenSSL
#      inside, no sanitizer or coverage instrumentation, no debug sections, the export whitelist or the ksl_ prefix).
#   6. publishToMavenCentral (skipped by --dry-run), then the portal steps and the checks after publishing.
#
# Usage: tools/release/local-release.sh <version> [--dry-run [--unsigned]] [--resume] [--repro] [--release-commit <sha>]
#                                       [--allow-over-limit] [--allow-toolchain-drift]
#   --dry-run    everything but the upload; the refusals of step 1 become warnings; signed when a key is configured, else
#                -Pkuicksilver.sign=false. The file count is that of the signed upload either way.
#   --unsigned   (with --dry-run) -Pkuicksilver.sign=false even with a key configured.
#   --resume     reuse the JNI libraries a previous run built and checked for this same commit (build/release/jni-artifacts).
#   --repro      build every JNI library and the jar a second time and compare them byte for byte (report only).
#   --release-commit <sha>   release a detached checkout of <sha> (an ancestor of main) instead of the tip of main.
#   --allow-over-limit       publish although the count is above the Central limits (30 days of grace, then refused).
#   --allow-toolchain-drift  warn instead of refusing when the NDK or Xcode differs from gradle/toolchains.toml.
# Env: KSL_GRADLE  the Gradle launcher, which sets its own --max-workers (default ./gradlew --max-workers=2)
#      KSL_CENTRAL_MAX_FILES (1167), KSL_CENTRAL_MAX_BYTES (78000000)  the portal's limits for this namespace
# Credentials (never in the repository, never printed): ~/.gradle/gradle.properties or ORG_GRADLE_PROJECT_* variables,
#   mavenCentralUsername / mavenCentralPassword, and signing.keyId + signing.password + signing.secretKeyRingFile
#   or signingInMemoryKey + signingInMemoryKeyId + signingInMemoryKeyPassword.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"; cd "$root"
. tools/check/llvm-tool.sh

version=""; dry=0; unsigned=0; resume=0; repro=0; release_commit=""; allow_over=0; allow_drift=0
while [ $# -gt 0 ]; do case "$1" in
  --dry-run) dry=1 ;; --unsigned) unsigned=1 ;; --resume) resume=1 ;; --repro) repro=1 ;; --allow-over-limit) allow_over=1 ;;
  --allow-toolchain-drift) allow_drift=1 ;; --release-commit) release_commit="${2:?--release-commit <sha>}"; shift ;;
  -h|--help) sed -n '2,/^set -euo/p' "$0" | sed '$d'; exit 0 ;;
  -*) echo "unknown option $1" >&2; exit 2 ;;
  *) [ -z "$version" ] || { echo "one version only" >&2; exit 2; }; version="$1" ;;
esac; shift; done
[ -n "$version" ] || { echo "usage: $0 <version> [--dry-run] [--resume] [--repro] (see --help)" >&2; exit 2; }

max_files="${KSL_CENTRAL_MAX_FILES:-1167}"; max_bytes="${KSL_CENTRAL_MAX_BYTES:-78000000}"
if [ -n "${KSL_GRADLE:-}" ]; then read -r -a G <<< "$KSL_GRADLE"; else G=(./gradlew --max-workers=2); fi   # a launcher sets its own --max-workers
out=build/release; logs="$out/logs"; art="$out/jni-artifacts"; m2="$root/$out/m2"
mkdir -p "$logs"
abi=$(sed -n 's/^#define KSL_ABI_VERSION \([0-9]*\)u/\1/p' kuicksilver-native/src/c/ksl.h)
ossl=$(sed -n 's/^version = "\(.*\)"/\1/p' gradle/openssl.toml)
head=$(git rev-parse HEAD); short=$(git rev-parse --short=7 HEAD)
sha() { (sha256sum "$@" 2>/dev/null || shasum -a 256 "$@") | cut -d' ' -f1; }
problems=0
refuse() { # a precondition: fatal for a release, a warning in a dry run
  if [ "$dry" = 1 ]; then echo "  WARN (a release would refuse): $*"; problems=$((problems+1)); else echo "REFUSED: $*" >&2; exit 1; fi
}
once_more() { "$@" || { echo "(failed; one retry: Docker image builds and yum mirrors fail transiently)"; "$@"; }; }
n=0
step() { # <name> <command...>: runs it with its output in build/release/logs/<n>.log, stops the release on failure
  local name="$1" log; shift; n=$((n+1)); log="$logs/$(printf '%02d' $n).log"
  printf '[%2d] %-58s' "$n" "$name"; local t0=$SECONDS
  if "$@" > "$log" 2>&1; then echo "ok ($((SECONDS-t0)) s)"; else echo "FAIL ($((SECONDS-t0)) s, see $log)"; tail -25 "$log" | sed 's/^/     | /'; exit 1; fi
}

echo "== Kuicksilver $version from $short ($([ "$dry" = 1 ] && echo "DRY RUN, nothing is uploaded" || echo "RELEASE to the Central Portal"))"

# ---------------------------------------------------------------------------------------------------------------- 1. gate
echo "-- preconditions"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-(alpha|beta|rc)\.?[0-9]+)?$ ]] || { echo "REFUSED: version '$version' is not X.Y.Z[-alpha|beta|rcN]" >&2; exit 1; }
[ -z "$(git status --porcelain)" ] || refuse "the working tree is not clean (git status)"
branch=$(git symbolic-ref --short -q HEAD || true)
if [ -n "$release_commit" ]; then
  [ "$(git rev-parse "$release_commit^{commit}" 2>/dev/null)" = "$head" ] || refuse "--release-commit $release_commit is not HEAD ($short)"
  git merge-base --is-ancestor HEAD main 2>/dev/null || refuse "release commit $short is not contained in main"
elif [ "$branch" != main ]; then
  refuse "HEAD is ${branch:-detached} ($short), not main (or pass --release-commit <sha> for a commit of main)"
fi
git branch -r --contains HEAD 2>/dev/null | grep -qE '^ *origin/main$' || echo "  note: $short is not on origin/main yet; push main before the tag (step 6)"
if git rev-parse -q --verify "refs/tags/v$version" >/dev/null; then
  [ "$(git rev-parse "v$version^{commit}")" = "$head" ] || refuse "tag v$version exists and names another commit"
fi
grep -qE "^## \[$version\]" CHANGELOG.md || refuse "CHANGELOG.md has no '## [$version]' section (move [Unreleased] under the version)"
# the local gate: tools/ci/local-matrix.sh writes build/ci/gate/<commit>.stamp at its end
stamp="build/ci/gate/$head.stamp"
gate() { sed -n "s/^$1=//p" "$stamp" 2>/dev/null | head -1; }
if [ ! -f "$stamp" ]; then
  refuse "no local gate for $short: run tools/ci/local-matrix.sh --with-interop --with-windows on this commit ($stamp)"
else
  [ "$(gate result)" = pass ] || refuse "the local gate of $short did not pass ($(gate failed) failed step(s), tree $(gate tree); $stamp)"
  for o in skip_android skip_docker; do [ "$(gate "$o")" = 0 ] || refuse "the local gate of $short ran with --${o//_/-}"; done
  for o in with_interop with_windows; do [ "$(gate "$o")" = 1 ] || refuse "the local gate of $short ran without --${o//_/-}"; done
  echo "  local gate: $(gate steps) steps passed on $short ($(gate finished))"
fi
# toolchains pinned in gradle/toolchains.toml (the CI setup action installs exactly these)
drift() { if [ "$allow_drift" = 1 ]; then echo "  WARN: $*"; else refuse "$* (or --allow-toolchain-drift)"; fi; }
ndk_pin=$(sed -n 's/^ndk = "\(.*\)".*/\1/p' gradle/toolchains.toml); xcode_pin=$(sed -n 's/^xcode = "\(.*\)".*/\1/p' gradle/toolchains.toml)
ndk_dir="${ANDROID_NDK_ROOT:-$HOME/Library/Android/sdk/ndk/$ndk_pin}"
[ "$(sed -n 's/^Pkg.Revision *= *//p' "$ndk_dir/source.properties" 2>/dev/null)" = "$ndk_pin" ] \
  || drift "NDK $ndk_pin is not installed (sdkmanager --install 'ndk;$ndk_pin'); the Android libraries would use $(ls "$HOME/Library/Android/sdk/ndk" 2>/dev/null | sort -V | tail -1)"
xcode_have=$(xcodebuild -version 2>/dev/null | sed -n 's/^Xcode //p')
[ "$xcode_have" = "$xcode_pin" ] || drift "Xcode $xcode_have is selected, gradle/toolchains.toml pins $xcode_pin (xcode-select -s)"
# the Android SDK for the AAR publications: local.properties (sdk.dir) or ANDROID_HOME, else the default macOS location
if ! grep -qs '^sdk.dir=' local.properties && [ -z "${ANDROID_HOME:-}${ANDROID_SDK_ROOT:-}" ]; then
  [ -d "$HOME/Library/Android/sdk" ] && export ANDROID_HOME="$HOME/Library/Android/sdk" || refuse "no Android SDK (sdk.dir in local.properties or ANDROID_HOME)"
fi
# credentials and signing: presence only, values are never read into this script's output
gp="${GRADLE_USER_HOME:-$HOME/.gradle}/gradle.properties"
has() { local v="ORG_GRADLE_PROJECT_$1"; [ -n "${!v:-}" ] || grep -qE "^[[:space:]]*$(printf '%s' "$1" | sed 's/\./\\./g')[[:space:]]*[=:][[:space:]]*[^[:space:]]" "$gp" 2>/dev/null; }
signed=0
if has signingInMemoryKey && has signingInMemoryKeyId && has signingInMemoryKeyPassword; then signed=1
elif has signing.keyId && has signing.password && has signing.secretKeyRingFile; then
  ring=$(sed -n 's/^[[:space:]]*signing\.secretKeyRingFile[[:space:]]*[=:][[:space:]]*//p' "$gp" 2>/dev/null | tail -1)
  if [ -z "$ring" ] || [ -f "$ring" ]; then signed=1; else refuse "signing.secretKeyRingFile in $gp names a missing file"; fi
fi
grep -qE '^[[:space:]]*kuicksilver\.sign[[:space:]]*=[[:space:]]*false' "$gp" gradle.properties 2>/dev/null && refuse "kuicksilver.sign=false is set in a gradle.properties"
[ "$signed" = 1 ] && echo "  signing key: configured" || refuse "no signing key (signing.keyId/password/secretKeyRingFile or signingInMemoryKey*) in $gp or the environment"
if has mavenCentralUsername && has mavenCentralPassword; then echo "  Central Portal token: configured"
else [ "$dry" = 1 ] && echo "  Central Portal token: not configured (not needed for a dry run)" || refuse "no mavenCentralUsername/mavenCentralPassword in $gp or the environment"; fi
if [ "$unsigned" = 1 ]; then
  [ "$dry" = 1 ] || { echo "REFUSED: --unsigned is for --dry-run only" >&2; exit 1; }
  signed=0; echo "  --unsigned: the local publication is not signed"
fi
sign_args=(); [ "$signed" = 1 ] || sign_args=(-Pkuicksilver.sign=false)
P=(-Pkuicksilver.version="$version" -Pkuicksilver.openssl.prebuilt=true -x :kuicksilver-native:buildJniHost ${sign_args[@]+"${sign_args[@]}"})

# ------------------------------------------------------------------------------------------------------------- 2. OpenSSL
echo "-- OpenSSL $ossl (all twelve targets rebuilt from the verified tarball)"
step "openssl: fetch and verify"                               bash tools/openssl/fetch.sh
# security review 2026-10-14, finding 3: nothing of build/openssl (shared between worktrees, downloaded by CI) or of the build
# cache is trusted for a release; -Pkuicksilver.openssl.prebuilt=true below then reuses exactly these builds, after checking
# their provenance.txt (openssl.gradle.kts)
export KSL_OPENSSL_FRESH=1
rm -rf build/openssl build/openssl-prefixed
for t in linux-x64 linux-arm64 mingw-x64; do   # Docker, one container at a time
  step "openssl: build $t (Docker)"                            once_more nice -n 10 bash tools/openssl/build-docker.sh "$t"
  step "openssl: no-sslkeylog ($t)"                            bash tools/check/keylog-disabled.sh "build/openssl/$t/include"
done
for t in macos-arm64 macos-x64 ios-arm64 ios-sim-arm64 android-arm64 android-x86_64 android-arm linux-x64-kn linux-arm64-kn; do
  step "openssl: build $t"                                     nice -n 10 bash tools/openssl/build.sh "$t"
  step "openssl: no-sslkeylog ($t)"                            bash tools/check/keylog-disabled.sh "build/openssl/$t/include"
done

# ------------------------------------------------------------------------------------------------------- 3. JNI libraries
echo "-- JNI libraries (ksl ABI $abi)"
classifiers="osx-aarch_64 osx-x86_64 linux-x86_64 linux-aarch_64 windows-x86_64"
lib_of() { case "$1" in osx-*) echo "libksl_${abi}_${1/-/_}.dylib" ;; linux-*) echo "libksl_${abi}_${1/-/_}.so" ;; windows-*) echo "libksl_${abi}_${1/-/_}.dll" ;; esac; }
build_jni() { # <classifier> <out dir, relative to the repository>: tools/build-jni.sh where CI builds it
  local cls="$1" o="$2"; rm -rf "$o"
  case "$cls" in
    osx-*) bash tools/build-jni.sh "$cls" "$root/$o" ;;
    linux-x86_64)   docker_jni linux/amd64 kuicksilver-openssl-linux-x64 "$cls" "$o" ;;
    linux-aarch_64) docker_jni linux/arm64 kuicksilver-openssl-linux-arm64 "$cls" "$o" ;;
    windows-x86_64) nice -n 10 bash tools/ci/jni-windows.sh "$o" ;;   # includes its export and export-directory checks
  esac
}
docker_jni() { # as tools/ci/docker-jvm.sh step 1: manylinux2014 gcc 10 and the JNI headers of the image's OpenJDK
  nice -n 10 bash tools/ci/docker-run.sh "$1" "$2" "set -e; [ -d /usr/lib/jvm/java/include ] || yum -q -y install java-11-openjdk-devel >/dev/null 2>&1 || true
    CC=/opt/rh/devtoolset-10/root/usr/bin/gcc JAVA_HOME=/usr/lib/jvm/java bash tools/build-jni.sh $3 $4"
}
check_lib() { # <classifier> <dir>: the checks CI runs on that library, plus its imports and the OpenSSL inside
  local cls="$1" d="$2" lib; lib=$(lib_of "$cls"); local f="$d/$cls/$lib" r="$d/resources/META-INF/native"
  [ -f "$f" ] || { echo "FAIL: $f missing"; return 1; }
  cmp -s "$f" "$r/$lib" || { echo "FAIL: $r/$lib differs from $f"; return 1; }
  [ "$(awk -v l="$lib" '$2 == l || $2 == "*"l {print $1}' "$r/manifest.sha256")" = "$(sha "$f")" ] || { echo "FAIL: manifest.sha256 does not match $lib"; return 1; }
  echo "OK: manifest.sha256 matches $lib"
  # the pinned OpenSSL inside, no sanitizer/coverage instrumentation or debug sections, the export whitelist
  bash tools/check/native-release.sh "$f" "$(case "$cls" in osx-*) echo macos ;; linux-*) echo linux ;; *) echo windows ;; esac)" || return 1
  local deps bad
  case "$cls" in
    osx-*)
      local want; want=$([ "$cls" = osx-aarch_64 ] && echo arm64 || echo x86_64)
      [ "$(lipo -archs "$f")" = "$want" ] || { echo "FAIL: $lib is $(lipo -archs "$f"), not $want"; return 1; }
      deps=$(otool -L "$f" | tail -n +2 | awk '{print $1}' | grep -vx "$(otool -D "$f" | tail -1)")   # minus its own install name
      bad=$(printf '%s\n' "$deps" | grep -vE '^(/usr/lib/libSystem\.B\.dylib|/usr/lib/libobjc\.A\.dylib|/System/Library/Frameworks/[A-Za-z]+\.framework/.*)$' || true) ;;
    linux-*)
      bash tools/check/glibc-floor.sh "$f" 2.17 || return 1
      deps=$("$(ksl_llvm_tool llvm-readelf)" -d "$f" | sed -n 's/.*(NEEDED).*\[\(.*\)\]/\1/p')
      bad=$(printf '%s\n' "$deps" | grep -vE '^(libc\.so\.6|libpthread\.so\.0|libdl\.so\.2|ld-linux.*)$' || true) ;;
    windows-*)   # tools/ci/jni-windows.sh already ran the export whitelist and the export-directory check inside its container
      deps=$("$(ksl_llvm_tool llvm-objdump)" -p "$f" | sed -n 's/^ *DLL Name: *//p')
      bad=$(printf '%s\n' "$deps" | grep -viE '^(kernel32|msvcrt|ws2_32|crypt32|bcrypt|advapi32|user32|api-ms-win-crt-[a-z-]+-l1-1-0)\.dll$' || true) ;;
  esac
  [ -z "$(printf '%s' "$bad" | tr -d '[:space:]')" ] || { echo "FAIL: $lib imports $(echo $bad)"; return 1; }
  echo "OK: $lib imports only $(echo $deps)"
}
mkdir -p "$art"
for cls in $classifiers; do
  d="$art/jni-$cls"
  if [ "$resume" = 1 ] && [ "$(cat "$d/.built-for" 2>/dev/null)" = "$head $ossl" ]; then
    echo "     jni $cls: reused (built and checked for $short by an earlier run)"; continue
  fi
  rm -f "$d/.built-for"
  step "jni: build $cls"                                       build_jni "$cls" "$d"
  step "jni: check $cls"                                       check_lib "$cls" "$d"
  echo "$head $ossl" > "$d/.built-for"
done
step "jni: collect the five libraries"                         bash tools/ci/collect-jni.sh "$art"

# ---------------------------------------------------------------------------------------------------------------- 4. jar
echo "-- kuicksilver-native jar"
jar="kuicksilver-native/build/libs/kuicksilver-native-jvm-$version.jar"
step "jvm: jar with every JNI library"                         "${G[@]}" "${P[@]}" :kuicksilver-native:jvmJar
step "jvm: jar lists all five libraries"                       bash tools/ci/collect-jni.sh --check-jar "$jar"
check_jar() { # the libraries in the jar are the collected ones; the manifest names the pinned OpenSSL and this commit
  local dst=kuicksilver-native/build/jni/resources/META-INF/native e mf
  for e in $(cd "$dst" && ls libksl_* manifest.sha256); do
    [ "$(unzip -p "$jar" "META-INF/native/$e" | sha)" = "$(sha "$dst/$e")" ] || { echo "FAIL: META-INF/native/$e in the jar differs from $dst/$e"; return 1; }
    echo "OK: META-INF/native/$e"
  done
  [ "$(unzip -l "$jar" 'META-INF/native/*' | grep -c 'META-INF/native/libksl_')" = 5 ] || { echo "FAIL: not exactly five libraries in the jar"; return 1; }
  mf=$(unzip -p "$jar" META-INF/MANIFEST.MF | tr -d '\r'); echo "$mf"
  printf '%s\n' "$mf" | grep -qx "OpenSSL-Version: $ossl" || { echo "FAIL: manifest OpenSSL-Version is not $ossl"; return 1; }
  printf '%s\n' "$mf" | grep -qx "Ksl-ABI: $abi" || { echo "FAIL: manifest Ksl-ABI is not $abi"; return 1; }
  printf '%s\n' "$mf" | grep -qx "Ksl-Revision: $short" || { echo "FAIL: manifest Ksl-Revision is not $short"; return 1; }
}
step "jvm: jar libraries and manifest"                         check_jar
echo "     $jar: $(wc -c < "$jar" | tr -d ' ') bytes, sha256 $(sha "$jar")"

if [ "$repro" = 1 ]; then
  echo "-- reproducibility (second build, compared byte for byte; reported, never fatal)"
  repro_libs() {
    local cls lib a b rc=0
    for cls in $classifiers; do
      lib=$(lib_of "$cls"); a="$art/jni-$cls/$cls/$lib"; b="$out/repro/jni-$cls/$cls/$lib"
      build_jni "$cls" "$out/repro/jni-$cls" >/dev/null 2>&1 || { echo "FAIL $cls: second build failed"; rc=1; continue; }
      if cmp -s "$a" "$b"; then echo "SAME $cls $lib $(sha "$a")"; else echo "DIFF $cls $lib $(sha "$a") vs $(sha "$b")"; rc=1; fi
    done; return $rc
  }
  repro_jar() {
    local first; first=$(sha "$jar"); cp "$jar" "$out/repro/first.jar"
    "${G[@]}" "${P[@]}" :kuicksilver-native:jvmJar --rerun >/dev/null || return 1
    if [ "$(sha "$jar")" = "$first" ]; then echo "SAME jar $first"; else echo "DIFF jar $first vs $(sha "$jar")"; return 1; fi
  }
  mkdir -p "$out/repro"
  if repro_libs > "$out/repro/libs.txt" 2>&1; then echo "     libraries: all five byte-identical"; else echo "     libraries: differences, see $out/repro/libs.txt"; fi
  sed 's/^/       /' "$out/repro/libs.txt"
  if repro_jar > "$out/repro/jar.txt" 2>&1; then echo "     jar: byte-identical"; else echo "     jar: differs, see $out/repro/jar.txt"; fi
  sed 's/^/       /' "$out/repro/jar.txt"
fi

# --------------------------------------------------------------------------------------------- 5. local publication and count
echo "-- publication into $out/m2 (count against the Central limits)"
rm -rf "$m2"
step "publish: publishToMavenLocal ($([ "$signed" = 1 ] && echo signed || echo unsigned))" "${G[@]}" "${P[@]}" -Dmaven.repo.local="$m2" publishToMavenLocal
count() { # what the Central bundle holds: every artifact + .md5 + .sha1 + .asc (vanniktech 0.37: no maven-metadata, no checksums of .asc)
  local asc_est=870
  find "$m2/io/kuicksilver" -path "*/$version/*" -type f ! -name 'maven-metadata*' ! -name '*.md5' ! -name '*.sha1' ! -name '*.sha256' ! -name '*.sha512' |
  while read -r f; do printf '%s %s %s\n' "$(basename "$(dirname "$(dirname "$f")")")" "$(wc -c < "$f" | tr -d ' ')" "$f"; done |
  awk -v asc="$asc_est" '
    { a=$1; m=a; sub(/-(jvm|android|iosarm64|iossimulatorarm64|macosarm64|linuxx64|linuxarm64|mingwx64)$/, "", m)
      if ($3 ~ /\.asc$/) { ascb[m]+=$2; nasc[m]++; next }
      if (!((m, a) in pub)) { pub[m, a]=1; pubs[m]++ }; arts[m]++; bytes[m]+=$2 }
    END { for (m in arts) printf "%s %d %d %d %d\n", m, pubs[m], arts[m], arts[m]*4, bytes[m] + arts[m]*72 + (nasc[m] ? ascb[m] : arts[m]*asc) }' |
  sort | awk -v maxf="$max_files" -v maxb="$max_bytes" -v signed="$signed" '
    BEGIN { printf "     %-26s %5s %10s %8s %12s\n", "module", "pubs", "artifacts", "upload", "bytes" }
    { printf "     %-26s %5d %10d %8d %12d\n", $1, $2, $3, $4, $5; P+=$2; A+=$3; T+=$4; B+=$5 }
    END { printf "     %-26s %5d %10d %8d %12d  (%.2f MB)\n", "total", P, A, T, B, B/1000000
      printf "     Central limits: %d files, %d bytes: %s\n", maxf, maxb, (T<=maxf && B<=maxb) ? "within" : "ABOVE"
      if (!signed) print "     (unsigned here: each .asc counted as 870 bytes, an armored 4096-bit RSA signature)"
      exit (T<=maxf && B<=maxb) ? 0 : 3 }'
}
set +e; count | tee "$out/count.txt"; within=${PIPESTATUS[0]}; set -e
[ "$within" = 0 ] || [ "$within" = 3 ] || { echo "FAIL: counting the publication"; exit 1; }
if [ "$within" = 3 ]; then
  [ "$allow_over" = 1 ] && echo "  WARN: above the Central limits (--allow-over-limit)" || refuse "the deployment is above the Central limits (ask central-support@sonatype.com, or --allow-over-limit within the 30 days of grace)"
fi
# security review 2026-10-14, findings 3 and 4: the Android and Kotlin/Native artifacts carry their own static OpenSSL
check_aar() {
  local aar; aar=$(ls "$m2"/io/kuicksilver/kuicksilver-native-android/"$version"/kuicksilver-native-android-"$version".aar 2>/dev/null | head -1)
  [ -n "$aar" ] || { echo "FAIL: no kuicksilver-native-android-$version.aar in $m2"; return 1; }
  bash tools/check/native-release.sh "$aar" aar
}
check_klibs() {
  local t k dir rc=0 n=0
  for t in iosarm64 iossimulatorarm64 macosarm64 linuxx64 linuxarm64 mingwx64; do
    k=$(ls "$m2"/io/kuicksilver/kuicksilver-native-"$t"/"$version"/*cinterop-ksl*.klib 2>/dev/null | head -1)
    [ -n "$k" ] || { echo "FAIL: no cinterop klib of kuicksilver-native-$t $version"; rc=1; continue; }
    dir="$out/klib-check/$t"; rm -rf "$dir"; mkdir -p "$dir/x"; unzip -q -o "$k" -d "$dir/x"
    find "$dir/x" -name 'lib*.a' -exec cp {} "$dir/" \;
    echo "== $t: $(basename "$k")"; bash tools/check/native-release.sh "$dir" archives || rc=1; n=$((n+1))
  done
  [ "$n" = 6 ] || rc=1; return $rc
}
step "android: AAR libksl.so (OpenSSL, exports, no sanitizers)"  check_aar
step "native: klib archives (OpenSSL, ksl_ prefix, no sanitizers)" check_klibs
echo "     local repository for consumer checks: $m2 (bash tools/check/consumer-smoke.sh $version with KSL_MAVEN_REPO=$m2)"

# --------------------------------------------------------------------------------------------------------------- 6. upload
if [ "$dry" = 1 ]; then
  echo; echo "dry run of $version on $short complete: nothing uploaded$([ "$problems" -gt 0 ] && echo "; $problems precondition(s) a release would refuse (WARN above)")."
  exit 0
fi
echo "-- upload"
step "release: publishToMavenCentral (one deployment, not released)" "${G[@]}" "${P[@]}" publishToMavenCentral
cat <<NEXT

Deployment uploaded; nothing is released yet. Next, by hand:
  1. https://central.sonatype.com/publishing/deployments: the deployment of io.kuicksilver $version must read VALIDATED
     (every module, every platform publication, the BOM, signatures and checksums). If it FAILED: Drop it, fix, run again.
  2. Press Publish. It reads PUBLISHING, then PUBLISHED (minutes); repo1.maven.org follows within about an hour.
  3. Consumer check from Central: samples/realtime-telemetry against io.kuicksilver:kuicksilver-bom:$version from
     mavenCentral() only (docs/release.md, "Every release", step 5).
  4. Then, and only then: git tag -s v$version -m "Kuicksilver $version" $short && git push origin main v$version,
     and the GitHub release from the tag with the CHANGELOG section.
NEXT
