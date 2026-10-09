#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# The CI matrix on the owner's macOS host: the same steps as .github/workflows/build.yml, in the same order,
# so moving to GitHub Actions is a change of runner, not of scripts. Docker provides Linux and mingw; the Android
# emulator must be running for the device steps. Usage: tools/ci/local-matrix.sh [--dry-run] [--skip-android] [--skip-docker] [--with-interop]
# --with-interop also runs the QUIC Interop Runner against every peer with both images (tools/interop/run-local.sh --check-required): hours, needs the peer images.
set -uo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"; cd "$root"
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
step "check: spdx, layers, abi"                $G checkSpdxHeaders checkLayerDependencies checkKotlinAbi
step "quic/http3: architecture checks"         $G checkQuicArchitecture checkHttp3Architecture
step "openssl: no-sslkeylog (macos-arm64)"      bash tools/check/keylog-disabled.sh build/openssl/macos-arm64/include
step "c-tests: macos-arm64 (ASan/UBSan)"        bash tools/c-test.sh macos-arm64
step "jvm: native/tls/ktor-network tests"       $G :kuicksilver-native:jvmTest :kuicksilver-tls:jvmTest :kuicksilver-ktor-network:jvmTest
step "jvm: quic/testing/interop tests"          $G :kuicksilver-quic:jvmTest :kuicksilver-testing:jvmTest :kuicksilver-interop:jvmTest
step "jvm: http3/ktor engine tests"             $G :kuicksilver-http3:jvmTest :kuicksilver-ktor-client:jvmTest :kuicksilver-ktor-server:jvmTest
step "sample: realtime-telemetry"               bash -c 'cd samples/realtime-telemetry && ../../gradlew --max-workers=2 -q jvmTest'
step "fuzz: regression corpus"                  $G :kuicksilver-quic:jvmTest --tests "io.kuicksilver.quic.fuzz.*" :kuicksilver-http3:jvmTest --tests "io.kuicksilver.http3.fuzz.*"
step "sim: Monte-Carlo (KSL_SIM_RUNS=200)"      $G :kuicksilver-testing:jvmTest -Pkuicksilver.sim.runs=200 --tests "io.kuicksilver.testing.MonteCarloTest"
step "bench: allocation gate"                   $G :kuicksilver-bench:jvmTest
step "jvm: exports whitelist (dylib)"           bash -c 'bash tools/check/exports.sh "$(ls kuicksilver-native/build/jni/osx-aarch_64/libksl_*_osx_aarch_64.dylib | tail -1)" macos'
step "android: AAR"                             $G :kuicksilver-native:bundleAndroidMainAar
step "android: size gate"                       bash tools/check/size.sh "$aar" "$SIZE_LIMIT"
step "android: 16 KiB pages"                    bash tools/check/page-align.sh "$aar"
if [ "$skip_android" = 0 ]; then
step "android: device tests (emulator)"         $G androidConnectedCheck
fi
step "native: macosArm64 tests"                 $G :kuicksilver-native:macosArm64Test :kuicksilver-tls:macosArm64Test :kuicksilver-ktor-network:macosArm64Test
step "native: quic/testing macosArm64 tests"    $G :kuicksilver-quic:macosArm64Test :kuicksilver-testing:macosArm64Test
step "native: http3/ktor macosArm64 tests"      $G :kuicksilver-http3:macosArm64Test :kuicksilver-ktor-client:macosArm64Test :kuicksilver-ktor-server:macosArm64Test
step "native: prefix whitelist (apple)"         bash -c 'for t in macos-arm64 ios-arm64 ios-sim-arm64; do bash tools/prefix/check-no-unprefixed.sh build/openssl-prefixed/$t/lib || exit 1; done'
step "native: link linux/ios-sim/mingw tests"   $G :kuicksilver-native:linkDebugTestLinuxX64 :kuicksilver-native:linkDebugTestLinuxArm64 :kuicksilver-native:linkDebugTestIosSimulatorArm64 :kuicksilver-native:linkDebugTestMingwX64
step "native: link quic tests linux/ios-sim/mingw" $G :kuicksilver-quic:linkDebugTestLinuxX64 :kuicksilver-quic:linkDebugTestLinuxArm64 :kuicksilver-quic:linkDebugTestIosSimulatorArm64 :kuicksilver-quic:linkDebugTestMingwX64
step "native: glibc floors"                     bash -c 'bash tools/check/glibc-floor.sh kuicksilver-native/build/bin/linuxX64/debugTest/test.kexe 2.19 && bash tools/check/glibc-floor.sh kuicksilver-native/build/bin/linuxArm64/debugTest/test.kexe 2.25'
step "native: prefix whitelist (linux/mingw)"   bash -c 'for t in linux-x64-kn linux-arm64-kn mingw-x64; do bash tools/prefix/check-no-unprefixed.sh build/openssl-prefixed/$t/lib || exit 1; done'
if [ "$skip_docker" = 0 ]; then
step "docker: c-tests linux-x64"                bash tools/ci/docker-run.sh linux/amd64 kuicksilver-openssl-linux-x64 "CC=/opt/rh/devtoolset-10/root/usr/bin/gcc SAN= bash tools/c-test.sh linux-x64"
step "docker: c-tests linux-arm64"              bash tools/ci/docker-run.sh linux/arm64 kuicksilver-openssl-linux-arm64 "CC=/opt/rh/devtoolset-10/root/usr/bin/gcc SAN= bash tools/c-test.sh linux-arm64"
step "docker: native test.kexe linux-x64"       bash tools/ci/docker-run.sh linux/amd64 kuicksilver-openssl-linux-x64 "kuicksilver-native/build/bin/linuxX64/debugTest/test.kexe"
step "docker: native test.kexe linux-arm64"     bash tools/ci/docker-run.sh linux/arm64 ubuntu:24.04 "kuicksilver-native/build/bin/linuxArm64/debugTest/test.kexe"   # K/N arm64 sysroot needs glibc 2.25 > manylinux2014
step "docker: quic test.kexe linux-x64"         bash tools/ci/docker-run.sh linux/amd64 kuicksilver-openssl-linux-x64 "kuicksilver-quic/build/bin/linuxX64/debugTest/test.kexe"
step "docker: quic test.kexe linux-arm64"       bash tools/ci/docker-run.sh linux/arm64 ubuntu:24.04 "kuicksilver-quic/build/bin/linuxArm64/debugTest/test.kexe"
step "docker: jvm linux-x64 (.so + tests)"      bash tools/ci/docker-jvm.sh linux-x86_64
step "docker: jvm linux-arm64 (KslDatagramIo, MultiLoop)" bash tools/ci/docker-jvm.sh linux-aarch_64   # the accelerated UDP, the multi-loop server and the Native-server guard run natively here
step "docker: system OpenSSL mode"              bash tools/ci/system-openssl.sh
fi
if [ "$with_interop" = 1 ]; then
T=handshake,transfer,longrtt,chacha20,multiplexing,retry,keyupdate,blackhole,ecn,amplificationlimit,handshakeloss,transferloss,handshakecorruption,transfercorruption,ipv6,v2,rebind-port,rebind-addr,http3
step "interop: jvm image"                       bash tools/interop/build-image.sh
step "interop: native image"                    bash tools/interop/build-image.sh --native
step "interop: jvm matrix, required cells"      bash tools/interop/run-local.sh --check-required -t $T
step "interop: native subset, required cells"   bash tools/interop/run-local.sh --check-required --image native -t handshake,transfer,retry,keyupdate,ecn,rebind-port,http3 quic-go ngtcp2 quinn msquic picoquic quiche
fi
echo; if [ "$failed" = 0 ]; then echo "local matrix: all $n steps passed"; else echo "local matrix: $failed of $n steps failed"; exit 1; fi
