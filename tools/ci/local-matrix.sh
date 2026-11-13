#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# The CI matrix on the owner's macOS host: the same steps as .github/workflows/build.yml, with the same names and
# the same module and interop case lists (tools/ci/matrix.sh), so moving to GitHub Actions is a change of runner, not of scripts. Docker provides Linux and mingw; the Android
# emulator must be running for the device steps.
# Usage: [KSL_GATE_WORKERS=n] tools/ci/local-matrix.sh [--dry-run] [--skip-android] [--skip-docker] [--with-interop] [--with-windows] [--with-browser]
#                                                      [--only <steps> | --from <n>]
# --with-interop also runs the QUIC Interop Runner against every peer with both images (tools/interop/run-local.sh --check-required): hours, needs the peer images.
# --with-windows also runs the JVM suites in the owner's Windows 11 VM against the mingw-w64 dll (CI's windows-jvm job) with
#   $KSL_WIN_JVM_TEST (default ~/.kuicksilver-tools/win-jvm-test, Parallels; outside the repository).
# --with-browser also runs ChromeWebTransportTest against the installed Chrome (headless; skipped by the test itself
#   when no Chrome or Chromium is installed).
# --only <steps> runs only the listed steps, a comma list of numbers and ranges (--only 25,48-49,52); --from <n> runs step
#   n and every later one (--from 44). The numbers are those of a full run with the same --skip-*/--with-* options (what --dry-run
#   with those options prints, the [n] of the output and build/ci/<n>.log), so a failure line maps onto --only n; the
#   steps left out print nothing. A step that reads what an earlier step produced (the AAR, the linked test executables,
#   the interop images, the ICMP marker files) refuses a selection without that step; a bad list, a number past the last
#   step and --only together with --from refuse too, all before the preflight and step 1. The preflight builds only the
#   OpenSSL (and its build image) that the selected steps read or run in, and resolves the dependencies only for the
#   Docker JVM steps.
# Gate record: every full run but a dry run writes build/ci/gate/<commit>.stamp (commit, options, selection=all, each step's
# result, result=pass only when every step passed and the tree was clean and on the same commit from start to end).
# tools/release/local-release.sh releases only a commit whose stamp says pass and selection=all with no --skip-* and with
# --with-interop --with-windows. A run with --only or --from is never a gate: it leaves the stamp alone and writes
# build/ci/gate/<commit>.partial instead (the selection, result=partial-pass or partial-fail, the selected steps' results).
set -uo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"; cd "$root" || exit 2
. tools/ci/matrix.sh
dry=0; skip_android=0; skip_docker=0; with_interop=0; with_windows=0; with_browser=0; only=""; from=""; selection=""
usage() { echo "usage: [KSL_GATE_WORKERS=n] tools/ci/local-matrix.sh [--dry-run] [--skip-android] [--skip-docker] [--with-interop] [--with-windows] [--with-browser] [--only <steps> | --from <n>] [-h|--help]"; }
refuse_args() { echo "local-matrix.sh: $*" >&2; usage >&2; exit 2; }
# an unknown option stops here, before any step: a mistyped flag must not start an hours-long gate with other options
while [ $# -gt 0 ]; do
  a="$1"; shift
  case "$a" in --only=*|--from=*) set -- "${a#*=}" "$@"; a="${a%%=*}" ;; esac
  case "$a" in --dry-run) dry=1 ;; --skip-android) skip_android=1 ;; --skip-docker) skip_docker=1 ;; --with-interop) with_interop=1 ;; --with-windows) with_windows=1 ;; --with-browser) with_browser=1 ;;
    --only|--from)
      [ $# -gt 0 ] && [ "${1#--}" = "$1" ] || refuse_args "$a needs a value: --only <steps> (e.g. 25,48-49,52) or --from <n>"
      [ -z "$selection" ] || [ "--${selection%%=*}" != "$a" ] || refuse_args "$a given twice (one list per run: --only 25,48-49)"
      [ -z "$selection" ] || refuse_args "--only and --from together (one selection per run; --only n-<last> is --from n)"
      if [ "$a" = --only ]; then only="$1"; selection="only=$1"; else from="$1"; selection="from=$1"; fi; shift ;;
    -h|--help) usage; exit 0 ;;
    *) refuse_args "unknown option '$a'" ;; esac
done
# Kotlin incremental compilation is off: a gate must not trust compiler state left by earlier builds in this checkout
# (Kotlin 2.4.20's classpath-snapshot diff failed on stale state in a gate run, 2026-10-16).
G="./gradlew --max-workers=${KSL_GATE_WORKERS:-2} -q -Pkotlin.incremental=false"; failed=0; n=0; results=""
head0=$(git rev-parse HEAD 2>/dev/null || echo unknown); dirty0=$(git status --porcelain 2>/dev/null | head -5); started=$(date -u +%Y-%m-%dT%H:%M:%SZ)
# A failed step keeps its evidence: the test XML and HTML reports it wrote are copied to build/ci/<n>-reports before a later
# step overwrites them, and the failing tests are listed in <n>.log and on the failure line. The third 0.2.1 gate lost the
# name of a flaky test this way: step 13's log had only "297 tests completed, 1 failed" (2026-10-23).
step_reports() { # <marker> <dest>: copies every test-results file and HTML test report newer than <marker> to <dest>, same relative paths
  # (never a heap dump: a safeguard, the dumps go to build/test-heap-dumps, not under build/reports; see step_dumps)
  local marker="$1" dest="$2"
  rm -rf "$dest"
  find . \( -name .git -o -name .worktrees -o -name .gradle -o -name node_modules -o -path ./build/ci \) -prune -o -type f -newer "$marker" \
    \( -path '*/build/test-results/*' -o -path '*/build/reports/tests/*' \) ! -name '*.hprof' -print0 > "$marker.list" 2>/dev/null
  [ -s "$marker.list" ] || { rm -f "$marker.list"; return 1; }
  mkdir -p "$dest" && tar --null -T "$marker.list" -cf - 2>/dev/null | tar -C "$dest" -xf -
  rm -f "$marker.list"
}
step_dumps() { # <marker> <log>: names every heap dump newer than <marker> (a test JVM out of heap, kuicksilver.test-jvm) under
  # the failure line and in <log>: hundreds of MB each, left where they are for a look and to be deleted afterwards
  local dumps
  dumps=$(find . \( -name .git -o -name .worktrees -o -name .gradle -o -name node_modules -o -path ./build/ci \) -prune -o -type f \
    -newer "$1" -path '*/build/test-heap-dumps/*.hprof' -print 2>/dev/null)
  [ -n "$dumps" ] || return 0
  { echo; echo "== heap dumps of this step (delete them when done):"; printf '%s\n' "$dumps"; } >> "$2"
  printf '%s\n' "$dumps" | sed 's/^/     | heap dump, delete when done: /'
}
failed_tests() { # <dir>: one line per failed or errored JUnit test case in the XML under <dir>: class.name: first message line
  # shellcheck disable=SC2016   # an awk program
  find "$1" -path '*/test-results/*' -name '*.xml' -type f -print0 2>/dev/null | xargs -0 awk '
    function attr(line, a,   m) { if (match(line, " " a "=\"[^\"]*\"")) { m = substr(line, RSTART + length(a) + 3, RLENGTH - length(a) - 4); return m } return "" }
    /<testcase / { tc = attr($0, "classname") "." attr($0, "name") }
    /<(failure|error)[ >]/ { msg = attr($0, "message"); gsub(/&#10;.*/, "", msg); gsub(/&quot;/, "\"", msg); gsub(/&lt;/, "<", msg); gsub(/&gt;/, ">", msg); gsub(/&amp;/, "\\&", msg)
      print "  " tc ": " substr(msg, 1, 200) }' 2>/dev/null | sort -u
}
# The step list (steps(), below) is walked twice. The first walk (mode=list) runs nothing: it numbers the steps, so a
# selection is checked against the real numbers before anything runs, and records what each step declares:
#   --needs <name>  it reads what the earlier step <name> produces: a selection must include that step, and it does not
#                   run unless that step passed in this run (never an artifact of an earlier run, never one a failed step left)
#   --after <name>  the same, but the earlier step only has to have run in this run (its marker files are what is read)
#   --pre <group>   the preflight it needs: macos, linux-x64, linux-arm64 or mingw (build/openssl/<target> read by a
#                   script, or the kuicksilver-openssl-<target> image it runs in, which the same Gradle task rebuilds when
#                   its Dockerfile changes); interop (the Linux one of the JVM interop image's platforms, resolved after
#                   the selection, below); deps (the
#                   dependency cache of the offline Docker JVM builds)
# The second walk (mode=run) runs, or with --dry-run lists, the selected steps.
mode=list; names=(); needs_of=(); after_of=(); pres=(); state=(); pick=(); ran=0
step_num() { # <name>: the number of the step of that name in this run's list, or status 1
  local k; for ((k = 1; k < ${#names[@]} + 1; k++)); do [ "${names[$k]-}" = "$1" ] && { echo "$k"; return 0; }; done; return 1
}
step() { # [--needs <name>]... [--after <name>]... [--pre <group>]... <name> <command...>
  local needs="" after="" pre="" k name
  while :; do case "$1" in
    --needs|--after) k=$(step_num "$2") || { echo "local-matrix.sh: internal error: '${*: -1}' $1 '$2', which is not an earlier step" >&2; exit 2; }
      if [ "$1" = --needs ]; then needs="$needs $k"; else after="$after $k"; fi; shift 2 ;;
    --pre) pre="$pre $2"; shift 2 ;;
    *) break ;; esac; done
  name="$1"; shift; n=$((n+1))
  if [ "$mode" = list ]; then names[n]="$name"; needs_of[n]="$needs"; after_of[n]="$after"; pres[n]="$pre"; return 0; fi
  [ -z "$selection" ] || [ "${pick[n]-}" = 1 ] || return 0   # not selected: nothing printed, nothing run
  ran=$((ran+1)); printf '[%2d] %-44s' "$n" "$name"
  if [ "$dry" = 1 ]; then echo "(dry run)"; return; fi
  local unmet=""
  for k in $needs; do [ "${state[k]-}" = ok ] || unmet="${unmet}step $k (${names[k]}) did not pass in this run; "; done
  for k in $after; do [ -n "${state[k]-}" ] || unmet="${unmet}step $k (${names[k]}) did not run in this run; "; done
  if [ -n "$unmet" ]; then   # what it would read is missing or left by an earlier run: a failure, never a pass on stale input
    mkdir -p build/ci; rm -rf "build/ci/$n-reports"; echo "not run: ${unmet}this step reads what that step produces" > "build/ci/$n.log"
    state[n]=FAIL; failed=$((failed+1)); results="${results}step.$n=FAIL $name"$'\n'; echo "FAIL (not run: ${unmet%; })"; return
  fi
  local log="build/ci/$n.log" marker="build/ci/.step-$n.start" reports="build/ci/$n-reports" tests; mkdir -p build/ci
  rm -rf "$reports"; touch "$marker"
  if "$@" > "$log" 2>&1; then echo "ok"; state[n]=ok; results="${results}step.$n=ok $name"$'\n'
  else
    state[n]=FAIL; failed=$((failed+1)); results="${results}step.$n=FAIL $name"$'\n'
    if step_reports "$marker" "$reports"; then
      tests=$(failed_tests "$reports")
      { echo; echo "== local-matrix: test reports of this step copied to $reports"; echo "== failed tests:"; printf '%s\n' "${tests:-  (none in the XML)}"; } >> "$log"
      echo "FAIL (see $log; reports $reports)"; [ -z "$tests" ] || printf '%s\n' "$tests" | head -10 | sed 's/^/     |/'
    else echo "FAIL (see $log)"; fi
    step_dumps "$marker" "$log"
  fi
  rm -f "$marker"
}
docker_ctests() { # <platform> <image> <target>: the ksl C tests in a Linux container. Their ICMP error-queue tests (udp_recverr_*) need
  # unshare(CLONE_NEWUSER | CLONE_NEWNET), which Docker's default seccomp profile refuses, so this container alone runs unconfined;
  # a run that still skips them (no unprivileged user namespaces) leaves no marker, and the step after both fails when neither ran
  local out rc
  out=$(KSL_DOCKER_OPTS="--security-opt seccomp=unconfined" bash tools/ci/docker-run.sh "$1" "$2" "CC=/opt/rh/devtoolset-10/root/usr/bin/gcc SAN= bash tools/c-test.sh $3" 2>&1); rc=$?
  printf '%s\n' "$out"
  if grep -q 'udp_recverr_ptb_parsed: OK' <<< "$out"; then mkdir -p build/ci; touch "build/ci/recverr-ran-$3"; fi
  return "$rc"
}
win_jvm() { # CI's windows-jvm on the Windows 11 VM; win-jvm-test's summary does not set its exit code, so it is read here
  local tool="${KSL_WIN_JVM_TEST:-$HOME/.kuicksilver-tools/win-jvm-test}" log rc summary k
  [ -x "$tool" ] || { echo "no $tool (the Windows VM runner)"; return 2; }
  # the dll of this run's mingw step; without it (--skip-docker, a selection, a failed step) it is built here: win-jvm-test
  # reuses a dll newer than the C sources, which says nothing about the OpenSSL it was linked against
  if ! k=$(step_num "docker: JNI library windows-x86_64 (mingw)") || [ "${state[k]-}" != ok ]; then
    echo "== the mingw dll is not from this run's mingw step: building it (tools/ci/jni-windows.sh)"
    bash tools/ci/jni-windows.sh build/jni-windows || return
  fi
  log=$("$tool" -w "$root" 2>&1); rc=$?; printf '%s\n' "$log"; [ "$rc" = 0 ] || return "$rc"
  summary=$(printf '%s\n' "$log" | sed -n '/^== summary/,$p')
  grep -Eq 'tests +[1-9]' <<< "$summary" || { echo "FAIL: no tests ran"; return 1; }
  ! grep -Eq 'NO REPORT|failed +[1-9]|errors +[1-9]' <<< "$summary"
}
interop_jvm_image() { # tools/interop/build-image.sh packs the Linux libksl.so it finds for the current ABI; only one built by
  # this run's Docker JVM steps is known to be of this commit, so without both of them the files are removed and rebuilt
  local nm k fresh=1
  for nm in "docker: jvm linux-x64 (.so + tests)" "docker: jvm linux-arm64 (.so + tests)"; do
    k=$(step_num "$nm") && [ "${state[k]-}" = ok ] || fresh=0
  done
  if [ "$fresh" = 0 ]; then
    echo "== the Linux libksl.so files are not from this run's Docker JVM steps: removing them, build-image.sh rebuilds the ones it packs"
    rm -f kuicksilver-native/build/jni/linux-x86_64/libksl_*.so kuicksilver-native/build/jni/linux-aarch_64/libksl_*.so
  fi
  bash tools/interop/build-image.sh
}
export SIZE_LIMIT="${SIZE_LIMIT:-3000000}"
aar=kuicksilver-native/build/outputs/aar/kuicksilver-native.aar
steps() { # the step list; step() above says what a walk of it does
step "lint: action/image pins"                 bash tools/check/pins.sh .
step "lint: C formatting (pinned clang-format)" bash tools/check/clang-format.sh
step "lint: documentation references"          bash tools/check/doc-refs.sh
step "lint: doc-refs negative controls"         bash tools/check/doc-refs-test.sh
step "lint: fuzz campaign.sh (stubs)"           bash tools/fuzz/campaign-test.sh
step "lint: interop peer images (stubs)"        bash tools/interop/peer-images-test.sh
step "lint: interop environment rules (fixtures)" bash tools/interop/environment-test.sh
step "lint: reliability report (fixtures)"      bash tools/report/reliability-test.sh
step "lint: RFC compliance summary table"      bash tools/check/rfc-table.sh
step "lint: HPACK tables and vectors"           python3 tools/http/gen-tables.py --check
step "lint: shared HTTP field vectors"         python3 tools/http/gen-field-vectors.py --check
step "lint: links (Markdown, llms.txt)"         bash tools/check/links.sh
step "lint: guide samples (guide-sync)"          bash tools/check/guide-sync.sh
step "lint: guide-sync negative controls"        bash tools/check/guide-sync-test.sh
step "lint: configuration tables vs the code"    bash tools/check/config-table.sh
step "lint: config-table negative controls"      bash tools/check/config-table-test.sh
step "lint: troubleshooting messages vs the code" bash tools/check/troubleshooting-msgs.sh
step "lint: troubleshooting-msgs negative controls" bash tools/check/troubleshooting-msgs-test.sh
step "lint: llms-full.txt is current"            bash tools/check/llms-full.sh --check
step "lint: llms-full negative controls"         bash tools/check/llms-full-test.sh
step "lint: ktlint"                            $G lintKotlin
step "check: dependency verification (every configuration)"  $G -I tools/check/resolve-all.init.gradle.kts -Pkuicksilver.resolveAll.strict=true --continue :build-logic:ksResolveAll ksResolveAll   # a metadata gap fails here, not in the late step resolving it
# shellcheck disable=SC2086
step "check: spdx, layers, abi"                $G $KSL_CHECKS
# shellcheck disable=SC2086
step "quic/http3: architecture checks"         $G $KSL_ARCH_CHECKS
step "docs: API reference and site (Dokka, no warnings)" bash tools/docs/site.sh 0.3.0-SNAPSHOT build/site   # the strict gate: an undocumented public declaration or an unresolved KDoc link fails here, not in pages.yml
step "compile: shared source sets (metadata)"  $G allMetadataJar   # commonMain/nativeMain/... of every module, the interop endpoint too: the per-target builds compile them only per target
step --pre macos "openssl: no-sslkeylog (macos-arm64)"      bash tools/check/keylog-disabled.sh build/openssl/macos-arm64/include
step --pre macos "c-tests: macos-arm64 (ASan/UBSan)"        bash tools/c-test.sh macos-arm64
step --pre macos "c-tests: macos-arm64 (TSan)"             env KSL_TSAN=1 bash tools/c-test.sh macos-arm64   # ~5 s; any data race fails
# shellcheck disable=SC2086
step "jvm: all module tests"                   $G $KSL_JVM_TESTS
step "jvm: coverage report"                     $G -Pkuicksilver.coverage :koverHtmlReportJvmTests :koverXmlReportJvmTests   # no threshold; build/reports/kover/htmlJvmTests
step "sample: realtime-telemetry"               bash -c 'cd samples/realtime-telemetry && ../../gradlew --max-workers=${KSL_GATE_WORKERS:-2} -q -Pkotlin.incremental=false jvmTest'
step "fuzz: regression corpus"                  $G "${KSL_FUZZ_ARGS[@]}"
step "sim: Monte-Carlo (KSL_SIM_RUNS=200)"      $G "${KSL_SIM_ARGS[@]}"
step "bench: allocation gate"                   $G :kuicksilver-bench:jvmTest
# the dylib the jar ships (buildJniHost's output) of this commit and this ABI, built here (up to date after the JVM tests;
# a selection may not run them)
step "jvm: exports whitelist (dylib)"           bash -c "$G :kuicksilver-native:buildJniHost"' && abi=$(sed -n "s/^#define KSL_ABI_VERSION \([0-9]*\)u/\1/p" kuicksilver-native/src/c/ksl.h) && bash tools/check/exports.sh "kuicksilver-native/build/jni/resources/META-INF/native/libksl_${abi}_osx_aarch_64.dylib" macos'
step "jvm: JNI library osx-x86_64 (Intel Macs)"  bash -c "$G :kuicksilver-native:opensslBuildMacosX64"' && bash tools/check/keylog-disabled.sh build/openssl/macos-x64/include && bash tools/build-jni.sh osx-x86_64 build/jni-osx-x86_64 && set -- build/jni-osx-x86_64/osx-x86_64/libksl_*_osx_x86_64.dylib && [ "$(lipo -archs "$1")" = x86_64 ] && bash tools/check/exports.sh "$1" macos'
step "android: AAR"                             $G :kuicksilver-native:bundleAndroidMainAar
step --needs "android: AAR" "android: size gate"                       bash tools/check/size.sh "$aar" "$SIZE_LIMIT"
step --needs "android: AAR" "android: 16 KiB pages"                    bash tools/check/page-align.sh "$aar"
step --needs "android: AAR" "android: consumer keep rules (R8)"        env KSL_R8_REQUIRED=1 bash tools/check/android-keep-rules.sh "$aar"   # a minified app must still load libksl (0.2.1 review)
step "jvm/android: service keep rules (R8)"     bash -c "$G :kuicksilver-ktor-client:jvmJar :kuicksilver-ktor-client:bundleAndroidMainAar"' && env KSL_R8_REQUIRED=1 bash tools/check/service-keep-rules.sh "$(ls -t kuicksilver-ktor-client/build/libs/kuicksilver-ktor-client-jvm-*.jar | head -1)" kuicksilver-ktor-client/build/outputs/aar/kuicksilver-ktor-client.aar'   # HttpClient() must still find the engine in a shrunk app
step --needs "android: AAR" "android: libksl.so exports, OpenSSL, no sanitizers"  bash tools/check/native-release.sh "$aar" aar   # all three ABIs (review 2026-10-14, finding 4)
step "check: native-release negative controls"   bash tools/check/native-release-test.sh
step "check: local-release refusals"             bash tools/release/local-release-test.sh
step "check: local-matrix step selection"        bash tools/ci/local-matrix-test.sh   # --dry-run only: the refusals of --only/--from
step "check: verify-release negative controls"   bash tools/verify/verify-release-test.sh   # offline fixtures: signatures, provenance, rebuilt libraries
if [ "$skip_android" = 0 ]; then
step "android: device tests (emulator)"         $G androidConnectedCheck
step "android: connection migration (emulator, host peer)" $G :kuicksilver-ktor-client:androidMigrationDeviceTest   # a server on the host, reached as 10.0.2.2 across the emulator's own network
fi
# shellcheck disable=SC2086
step "native: macosArm64 tests"                 $G $KSL_MACOS_TESTS
# the prefixed archives of this commit, built here: the iOS ones are otherwise built only by the two steps after this one
step "native: prefix whitelist (apple)"         bash -c "$G :kuicksilver-native:buildKslAMacosArm64 :kuicksilver-native:buildKslAIosArm64 :kuicksilver-native:buildKslAIosSimulatorArm64"' && for t in macos-arm64 ios-arm64 ios-sim-arm64; do bash tools/prefix/check-no-unprefixed.sh build/openssl-prefixed/$t/lib || exit 1; done'
# shellcheck disable=SC2046,SC2086
step "native: iosSimulatorArm64 tests"          $G $KSL_IOS_SIM_TESTS
step "native: compile iosArm64 (device)"        $G $KSL_IOS_COMPILE
# shellcheck disable=SC2046,SC2086
step "native: link linux/mingw tests"           $G $(ksl_tasks linkDebugTestLinuxX64 $KSL_LINK_MODULES) $(ksl_tasks linkDebugTestLinuxArm64 $KSL_LINK_MODULES) $(ksl_tasks linkDebugTestMingwX64 $KSL_LINK_MODULES)
step --needs "native: link linux/mingw tests" "native: glibc floors"                     bash -c 'bash tools/check/glibc-floor.sh kuicksilver-native/build/bin/linuxX64/debugTest/test.kexe 2.19 && bash tools/check/glibc-floor.sh kuicksilver-native/build/bin/linuxArm64/debugTest/test.kexe 2.25'
step "native: prefix whitelist (linux/mingw)"   bash -c "$G :kuicksilver-native:buildKslALinuxX64 :kuicksilver-native:buildKslALinuxArm64 :kuicksilver-native:buildKslAMingwX64"' && for t in linux-x64-kn linux-arm64-kn mingw-x64; do bash tools/prefix/check-no-unprefixed.sh build/openssl-prefixed/$t/lib || exit 1; done'
step --pre macos "repro: double build (macos-arm64)"        bash tools/check/double-build.sh macos-arm64
if [ "$skip_docker" = 0 ]; then
[ "$mode" = list ] || [ "$dry" = 1 ] || rm -f build/ci/recverr-ran-*   # the markers of this run only
step --pre linux-x64 "docker: c-tests linux-x64"                docker_ctests linux/amd64 kuicksilver-openssl-linux-x64 linux-x64
step --pre linux-arm64 "docker: c-tests linux-arm64"              docker_ctests linux/arm64 kuicksilver-openssl-linux-arm64 linux-arm64
step --after "docker: c-tests linux-x64" --after "docker: c-tests linux-arm64" "docker: Linux ICMP error-queue tests ran" bash -c 'ls build/ci/recverr-ran-* >/dev/null 2>&1 || { echo "udp_recverr_ptb_parsed skipped on every Linux runner"; exit 1; }'
# shellcheck disable=SC2086
step --needs "native: link linux/mingw tests" --pre linux-x64 "docker: test.kexe linux-x64 (all modules)"  bash tools/ci/run-kexe.sh linux/amd64 kuicksilver-openssl-linux-x64 linuxX64 $KSL_LINK_MODULES
# shellcheck disable=SC2086
step --needs "native: link linux/mingw tests" "docker: test.kexe linux-arm64 (all modules)" bash tools/ci/run-kexe.sh linux/arm64 "$KSL_UBUNTU_IMAGE" linuxArm64 $KSL_LINK_MODULES
step --pre linux-x64 --pre deps "docker: jvm linux-x64 (.so + tests)"      bash tools/ci/docker-jvm.sh linux-x86_64
step --pre linux-arm64 --pre deps "docker: jvm linux-arm64 (.so + tests)"    bash tools/ci/docker-jvm.sh linux-aarch_64   # the accelerated UDP, the multi-loop server and the Native-server guard run natively here
step "docker: system OpenSSL mode"              bash tools/ci/system-openssl.sh
step --pre linux-x64 "docker: h2spec (HTTP/2 server, JVM and linux-x64)" env KSL_GRADLE="$G" bash tools/interop/h2spec.sh jvm linux-x64   # all 146 cases of h2spec 2.6.0, one container at a time; needs the image pulled (docker pull summerwind/h2spec:2.6.0), never pulls it itself
step --pre mingw "docker: JNI library windows-x86_64 (mingw)" bash tools/ci/jni-windows.sh build/jni-windows
step "docker: deployment guide commands"         env KSL_GRADLE="$G" bash tools/check/deployment-guide.sh   # docs/guide/deployment.md "Checking a deployment": curl --http3-only and tcpdump against the engine, one container of the host's architecture
# CI windows-jvm runs the JVM suites of native, tls, quic, http3, ktor-network, ktor-client and ktor-server on windows-2025
# against this dll (-Pkuicksilver.openssl.prebuilt=true -x :kuicksilver-native:buildJniHost); there is no Windows host
# locally, so that step has no local counterpart (nor has CI's windows job running ksl_test.exe; tools/c-test.sh mingw-x64
# cross-builds it here).
fi
if [ "$with_interop" = 1 ]; then
# CI runs one job per image x peer (the same cases and peers); --check-required is scoped to each run's image, peers and cases
step --pre interop "interop: jvm image"                       interop_jvm_image
step "interop: native image"                    bash tools/interop/build-image.sh --native
# shellcheck disable=SC2086
step --needs "interop: jvm image" "interop: jvm image vs all peers, required cells"    bash tools/interop/run-local.sh --check-required -t "$KSL_INTEROP_CASES" $KSL_INTEROP_PEERS
# shellcheck disable=SC2086
step --needs "interop: native image" "interop: native image vs all peers, required cells" bash tools/interop/run-local.sh --check-required --image native -t "$KSL_INTEROP_NATIVE_CASES" $KSL_INTEROP_PEERS
fi
if [ "$with_windows" = 1 ]; then
step --pre mingw "windows: jvm module tests (VM, mingw dll)"  win_jvm
fi
if [ "$with_browser" = 1 ]; then
step "browser: Chrome WebTransport (headless)"  $G :kuicksilver-ktor-server:jvmTest --tests '*ChromeWebTransportTest*' -Pkuicksilver.browserTests=true
fi
}
n=0; steps; total=$n   # the list walk: numbers and declarations only, nothing runs
ranges() { # <numbers in ascending order...>: 1 2 3 5 -> 1-3,5
  local out="" lo="" hi="" k
  for k in "$@"; do
    if [ -n "$lo" ] && [ "$k" = $((hi + 1)) ]; then hi=$k; continue; fi
    [ -z "$lo" ] || out="$out,$lo$([ "$hi" = "$lo" ] || echo "-$hi")"; lo=$k; hi=$k
  done
  [ -z "$lo" ] || out="$out,$lo$([ "$hi" = "$lo" ] || echo "-$hi")"; echo "${out#,}"
}
picked() { local k; for ((k = 1; k <= total; k++)); do [ -n "$selection" ] && [ "${pick[k]-}" != 1 ] || echo "$k"; done; }
# shellcheck disable=SC2046   # one word per number
picked_ranges() { ranges $(picked); }
# a selection is checked here, before the preflight and step 1, like an unknown option
if [ -n "$selection" ]; then
  num_re='^[0-9]+$'; range_re='^([0-9]+)-([0-9]+)$'
  num() { # <digits>: the number in decimal (07 is 7), or a refusal when it is past every step
    local v="${1#"${1%%[!0]*}"}"; v="${v:-0}"
    if [ ${#v} -le 4 ] && [ "$v" -le "$total" ]; then echo "$v"; else echo $((total + 1)); fi
  }
  bad() { refuse_args "--${selection%%=*} '${selection#*=}': $* (steps are 1-$total with these options; --dry-run lists them)"; }
  if [ -n "$from" ] || [ "$selection" = "from=" ]; then
    case "$from" in ''|*[!0-9]*) bad "not a step number" ;; esac
    lo=$(num "$from"); [ "$lo" -ge 1 ] || bad "no step 0"; [ "$lo" -le "$total" ] || bad "past the last step"
    for ((k = lo; k <= total; k++)); do pick[k]=1; done
  else
    [ -n "$only" ] || bad "an empty step list"
    case "$only" in *[!0-9,-]*) bad "not a step number or a range a-b: only digits, commas and '-' (no spaces, no line breaks)" ;; esac
    case "$only" in ,*|*,|*,,*) bad "an empty item in the list" ;; esac
    IFS=, read -r -a items <<< "$only"
    for item in "${items[@]}"; do
      if [[ "$item" =~ $num_re ]]; then lo=$(num "$item"); hi=$lo
      elif [[ "$item" =~ $range_re ]]; then lo=$(num "${BASH_REMATCH[1]}"); hi=$(num "${BASH_REMATCH[2]}")
        [ "$lo" -le "$hi" ] || bad "the range '$item' runs backwards"
      else bad "'$item' is not a step number or a range a-b"; fi
      [ "$lo" -ge 1 ] || bad "no step 0"
      [ "$hi" -le "$total" ] || bad "'$item' is past the last step"
      for ((k = lo; k <= hi; k++)); do pick[k]=1; done
    done
  fi
  # a selected step that reads what another step produces needs that step in the same run
  missing=""
  for k in $(picked); do
    for d in ${needs_of[k]} ${after_of[k]}; do
      [ "${pick[d]-}" = 1 ] && continue
      echo "local-matrix.sh: step $k (${names[k]}) reads what step $d (${names[d]}) produces in the same run, and the selection leaves step $d out" >&2
      missing="$missing $d"
    done
  done
  if [ -n "$missing" ]; then
    for d in $missing; do pick[d]=1; done
    echo "local-matrix.sh: refused before any step ran; select those steps too: --only $(picked_ranges)" >&2; exit 2
  fi
  cnt=$(picked | wc -l | tr -d ' ')
  echo "selection: --${selection%%=*} ${selection#*=}: $([ "$cnt" = 1 ] && echo step || echo steps) $(picked_ranges), $cnt of $total; a partial run, never a gate (its record: build/ci/gate/<commit>.partial)"
fi
pre_wanted=" "; for k in $(picked); do pre_wanted="$pre_wanted${pres[k]} "; done
wants() { [[ "$pre_wanted" == *" $1 "* ]]; }
# "interop" (the JVM interop image) is the Linux OpenSSL of the platforms build-image.sh packs, found as it finds them:
# KSL_INTEROP_PLATFORMS, else the Docker server's architecture (not uname -m, which a Rosetta shell reports as x86_64 on
# an arm64 Docker). A dry run does not ask Docker and says that it shows the host's architecture instead.
if wants interop; then
  if [ -n "${KSL_INTEROP_PLATFORMS:-}" ]; then interop_platforms="$KSL_INTEROP_PLATFORMS"
  elif [ "$dry" = 1 ]; then case "$(uname -m)" in x86_64) interop_platforms=linux/amd64 ;; *) interop_platforms=linux/arm64 ;; esac
    echo "preflight: the JVM interop image packs the Docker server's architecture; this dry run shows the host's ($(uname -m)) instead"
  elif arch=$(docker version -f '{{.Server.Arch}}' 2>/dev/null) && [ -n "$arch" ]; then interop_platforms="linux/$arch"
  else echo "local matrix: refused before step 1: the JVM interop image needs Docker, and docker version does not answer" >&2; exit 1; fi
  # matched as build-image.sh matches them (amd64, arm64), so the preflight builds exactly what the image packs
  case "$interop_platforms" in *amd64*) pre_wanted="$pre_wanted linux-x64 " ;; esac
  case "$interop_platforms" in *arm64*) pre_wanted="$pre_wanted linux-arm64 " ;; esac
fi
# Preflight, before step 1: the steps that run scripts rather than Gradle tasks read build/openssl/<target> directly
# (c-tests, keylog check and double build: macos-arm64; the Docker c-tests and JNI builds: linux-x64, linux-arm64; the
# mingw dll: mingw-x64). CI builds those in jobs of their own; here a fresh worktree had none, and the Docker steps failed
# an hour into the gate (2026-10-21). The opensslBuild* tasks build what is missing or stale (the pin is one of their
# inputs) and do nothing otherwise; a failure refuses the gate before anything ran. Each target is built when a step of
# this run reads it (--pre in the step list): with every step, the same set as before steps could be selected; with a
# selection, a target no selected step reads is left alone (the Gradle steps build their own OpenSSL through task
# dependencies and need none of this).
preflight=()
wants macos && preflight+=(:kuicksilver-native:opensslBuildMacosArm64)
wants linux-x64 && preflight+=(:kuicksilver-native:opensslBuildLinuxX64)
wants linux-arm64 && preflight+=(:kuicksilver-native:opensslBuildLinuxArm64)
wants mingw && preflight+=(:kuicksilver-native:opensslBuildMingwX64)
if [ ${#preflight[@]} = 0 ]; then
  echo "preflight: no OpenSSL build is read by the selected steps"
elif [ "$dry" = 1 ]; then
  echo "preflight: $G ${preflight[*]} (dry run)"
else
  mkdir -p build/ci; printf 'preflight: OpenSSL for the script steps (%s) ... ' "${preflight[*]##*:opensslBuild}"
  # shellcheck disable=SC2086
  if $G "${preflight[@]}" > build/ci/preflight.log 2>&1; then echo ok
  else
    echo "FAIL (see build/ci/preflight.log)"; tail -15 build/ci/preflight.log | sed 's/^/     | /'
    echo "local matrix: refused before step 1; fix and run: ./gradlew --max-workers=2 ${preflight[*]}" >&2; exit 1
  fi
fi
# Preflight for the Docker JVM steps: their Gradle runs offline against the host's dependency cache, mounted read-only
# (tools/ci/docker-jvm.sh), so every artifact and every POM/.module it needs must be in that cache before it starts. The
# host's own cache cleanup deletes metadata files it does not see used (the descriptor cache answers instead), and an offline
# build with dependency verification then refuses the module: "No cached version of ... available for offline mode" for
# error_prone_annotations, an hour into the gate (2026-10-23). Resolving every configuration here, online and on the host
# (the init script of the "dependency verification" step, lenient), fetches whatever is missing; a failure of the build,
# or of a configuration the JVM suites run with, refuses the gate before anything ran.
if wants deps; then
  deps=(./gradlew "--max-workers=${KSL_GATE_WORKERS:-2}" -Pkotlin.incremental=false -I tools/check/resolve-all.init.gradle.kts --continue :build-logic:ksResolveAll ksResolveAll)
  if [ "$dry" = 1 ]; then
    echo "preflight: ${deps[*]} (dry run)"
  else
    printf 'preflight: dependencies of the offline Docker builds (host, online) ... '
    if "${deps[@]}" > build/ci/preflight-deps.log 2>&1 \
      && ! grep -Eq '^ksResolveAll [^ ]*:(jvm(Test)?(Compile|Runtime)Classpath|(compile|runtime)Classpath|kotlinCompiler(Plugin)?Classpath) (unresolved|failed)' build/ci/preflight-deps.log; then
      echo ok
    else
      echo "FAIL (see build/ci/preflight-deps.log)"
      grep -E '^ksResolveAll .*(unresolved|failed)|^> |FAILURE' build/ci/preflight-deps.log | head -15 | sed 's/^/     | /'
      echo "local matrix: refused before step 1: the Docker JVM steps would not resolve offline; fix and run: ${deps[*]}" >&2; exit 1
    fi
  fi
fi
mode=run; n=0; steps   # the run walk: the selected steps, in order
if [ "$dry" = 0 ]; then   # the gate record (see the header); a selection writes a partial record, never the stamp
  head1=$(git rev-parse HEAD 2>/dev/null || echo unknown); dirty1=$(git status --porcelain 2>/dev/null | head -5)
  tree=clean; [ -z "$dirty0$dirty1" ] || tree=dirty; [ "$head0" = "$head1" ] || tree="moved to $head1"
  if [ -z "$selection" ]; then
    record="build/ci/gate/$head0.stamp"; result=fail; [ "$failed" = 0 ] && [ "$tree" = clean ] && result=pass
  else
    record="build/ci/gate/$head0.partial"; result=partial-fail; [ "$failed" = 0 ] && [ "$tree" = clean ] && result=partial-pass
  fi
  mkdir -p build/ci/gate
  { echo "commit=$head0"; echo "result=$result"; echo "selection=${selection:-all}"
    [ -z "$selection" ] || echo "selected=$(picked_ranges)"
    echo "tree=$tree"; echo "started=$started"; echo "finished=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "host=$(uname -sm)"; echo "skip_android=$skip_android"; echo "skip_docker=$skip_docker"; echo "with_interop=$with_interop"
    echo "with_windows=$with_windows"; echo "with_browser=$with_browser"; echo "steps=$n"; echo "ran=$ran"; echo "failed=$failed"; printf '%s' "$results"; } > "$record"
  if [ -z "$selection" ]; then echo "gate record: $record (result=$result, tree $tree)"
  else echo "partial record: $record (result=$result, tree $tree; --${selection%%=*} ${selection#*=}: not a gate, no stamp written)"; fi
fi
echo
if [ "$dry" = 1 ]; then echo "local matrix: dry run, $ran of $total steps listed, none run"
elif [ -n "$selection" ]; then
  if [ "$failed" = 0 ]; then echo "local matrix: $([ "$ran" = 1 ] && echo "the selected step passed" || echo "the $ran selected steps passed") (--${selection%%=*} ${selection#*=}; a partial run, not a gate)"
  else echo "local matrix: $failed of the $ran selected steps failed (--${selection%%=*} ${selection#*=})"; exit 1; fi
elif [ "$failed" = 0 ]; then echo "local matrix: all $n steps passed"; else echo "local matrix: $failed of $n steps failed"; exit 1; fi
