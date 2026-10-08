#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# The CI matrix on the owner's macOS host: the same steps as .github/workflows/build.yml, with the same names and
# the same module and interop case lists (tools/ci/matrix.sh), so moving to GitHub Actions is a change of runner, not of scripts. Docker provides Linux and mingw; the Android
# emulator must be running for the device steps. Usage: tools/ci/local-matrix.sh [--dry-run] [--skip-android] [--skip-docker] [--with-interop]
# --with-interop also runs the QUIC Interop Runner against every peer with both images (tools/interop/run-local.sh --check-required): hours, needs the peer images.
set -uo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"; cd "$root"
. tools/ci/matrix.sh
dry=0; skip_android=0; skip_docker=0; with_interop=0
for a in "$@"; do case "$a" in --dry-run) dry=1 ;; --skip-android) skip_android=1 ;; --skip-docker) skip_docker=1 ;; --with-interop) with_interop=1 ;; esac; done
G="./gradlew --max-workers=2 -q"; failed=0; n=0
step() { # name command...
  local name="$1"; shift; n=$((n+1)); printf '[%2d] %-44s' "$n" "$name"
  if [ "$dry" = 1 ]; then echo "(dry run)"; return; fi
  local log="build/ci/$n.log"; mkdir -p build/ci
  if "$@" > "$log" 2>&1; then echo "ok"; else echo "FAIL (see $log)"; failed=$((failed+1)); fi
}
export SIZE_LIMIT="${SIZE_LIMIT:-3000000}"
aar=kuicksilver-native/build/outputs/aar/kuicksilver-native.aar
step "lint: action/image pins"                 bash tools/check/pins.sh .
# shellcheck disable=SC2086
step "check: spdx, layers, abi"                $G $KSL_CHECKS
# shellcheck disable=SC2086
step "quic/http3: architecture checks"         $G $KSL_ARCH_CHECKS
step "openssl: no-sslkeylog (macos-arm64)"      bash tools/check/keylog-disabled.sh build/openssl/macos-arm64/include
step "c-tests: macos-arm64 (ASan/UBSan)"        bash tools/c-test.sh macos-arm64
# shellcheck disable=SC2086
step "jvm: all module tests"                   $G $KSL_JVM_TESTS
step "sample: realtime-telemetry"               bash -c 'cd samples/realtime-telemetry && ../../gradlew --max-workers=2 -q jvmTest'
step "fuzz: regression corpus"                  $G "${KSL_FUZZ_ARGS[@]}"
step "sim: Monte-Carlo (KSL_SIM_RUNS=200)"      $G "${KSL_SIM_ARGS[@]}"
step "bench: allocation gate"                   $G :kuicksilver-bench:jvmTest
step "jvm: exports whitelist (dylib)"           bash -c 'bash tools/check/exports.sh "$(ls kuicksilver-native/build/jni/osx-aarch_64/libksl_*_osx_aarch_64.dylib | tail -1)" macos'
step "android: AAR"                             $G :kuicksilver-native:bundleAndroidMainAar
step "android: size gate"                       bash tools/check/size.sh "$aar" "$SIZE_LIMIT"
step "android: 16 KiB pages"                    bash tools/check/page-align.sh "$aar"
if [ "$skip_android" = 0 ]; then
step "android: device tests (emulator)"         $G androidConnectedCheck
fi
# shellcheck disable=SC2086
step "native: macosArm64 tests"                 $G $KSL_MACOS_TESTS
step "native: prefix whitelist (apple)"         bash -c 'for t in macos-arm64 ios-arm64 ios-sim-arm64; do bash tools/prefix/check-no-unprefixed.sh build/openssl-prefixed/$t/lib || exit 1; done'
# shellcheck disable=SC2046,SC2086
step "native: link ios-sim tests"               $G $(ksl_tasks linkDebugTestIosSimulatorArm64 $KSL_LINK_MODULES)
# shellcheck disable=SC2046,SC2086
step "native: link linux/mingw tests"           $G $(ksl_tasks linkDebugTestLinuxX64 $KSL_LINK_MODULES) $(ksl_tasks linkDebugTestLinuxArm64 $KSL_LINK_MODULES) $(ksl_tasks linkDebugTestMingwX64 $KSL_LINK_MODULES)
step "native: glibc floors"                     bash -c 'bash tools/check/glibc-floor.sh kuicksilver-native/build/bin/linuxX64/debugTest/test.kexe 2.19 && bash tools/check/glibc-floor.sh kuicksilver-native/build/bin/linuxArm64/debugTest/test.kexe 2.25'
step "native: prefix whitelist (linux/mingw)"   bash -c 'for t in linux-x64-kn linux-arm64-kn mingw-x64; do bash tools/prefix/check-no-unprefixed.sh build/openssl-prefixed/$t/lib || exit 1; done'
step "repro: double build (macos-arm64)"        bash tools/check/double-build.sh macos-arm64
if [ "$skip_docker" = 0 ]; then
step "docker: c-tests linux-x64"                bash tools/ci/docker-run.sh linux/amd64 kuicksilver-openssl-linux-x64 "CC=/opt/rh/devtoolset-10/root/usr/bin/gcc SAN= bash tools/c-test.sh linux-x64"
step "docker: c-tests linux-arm64"              bash tools/ci/docker-run.sh linux/arm64 kuicksilver-openssl-linux-arm64 "CC=/opt/rh/devtoolset-10/root/usr/bin/gcc SAN= bash tools/c-test.sh linux-arm64"
step "docker: native test.kexe linux-x64"       bash tools/ci/docker-run.sh linux/amd64 kuicksilver-openssl-linux-x64 "kuicksilver-native/build/bin/linuxX64/debugTest/test.kexe"
step "docker: native test.kexe linux-arm64"     bash tools/ci/docker-run.sh linux/arm64 "$KSL_UBUNTU_IMAGE" "kuicksilver-native/build/bin/linuxArm64/debugTest/test.kexe"
step "docker: quic test.kexe linux-x64"         bash tools/ci/docker-run.sh linux/amd64 kuicksilver-openssl-linux-x64 "kuicksilver-quic/build/bin/linuxX64/debugTest/test.kexe"
step "docker: quic test.kexe linux-arm64"       bash tools/ci/docker-run.sh linux/arm64 "$KSL_UBUNTU_IMAGE" "kuicksilver-quic/build/bin/linuxArm64/debugTest/test.kexe"
step "docker: jvm linux-x64 (.so + tests)"      bash tools/ci/docker-jvm.sh linux-x86_64
step "docker: jvm linux-arm64 (.so + tests)"    bash tools/ci/docker-jvm.sh linux-aarch_64   # the accelerated UDP, the multi-loop server and the Native-server guard run natively here
step "docker: system OpenSSL mode"              bash tools/ci/system-openssl.sh
fi
if [ "$with_interop" = 1 ]; then
# CI runs one job per image x peer (the same cases and peers); --check-required is scoped to each run's image, peers and cases
step "interop: jvm image"                       bash tools/interop/build-image.sh
step "interop: native image"                    bash tools/interop/build-image.sh --native
# shellcheck disable=SC2086
step "interop: jvm image vs all peers, required cells"    bash tools/interop/run-local.sh --check-required -t "$KSL_INTEROP_CASES" $KSL_INTEROP_PEERS
# shellcheck disable=SC2086
step "interop: native image vs all peers, required cells" bash tools/interop/run-local.sh --check-required --image native -t "$KSL_INTEROP_NATIVE_CASES" $KSL_INTEROP_PEERS
fi
echo; if [ "$failed" = 0 ]; then echo "local matrix: all $n steps passed"; else echo "local matrix: $failed of $n steps failed"; exit 1; fi
