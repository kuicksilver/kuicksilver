#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# The module and test-case lists of the CI matrix, sourced by tools/ci/local-matrix.sh, tools/ci/docker-jvm.sh and every
# step of .github/workflows/build.yml that runs Gradle tests or the interop runner: the local gate and GitHub Actions
# cannot drift apart in what they test (review I2). Usage: . tools/ci/matrix.sh  (defines variables, runs nothing)
# shellcheck disable=SC2034   # every variable is used by the scripts that source this file

# Every library module with a JVM test suite (kuicksilver-bench is the allocation gate, run on its own).
KSL_MODULES="kuicksilver-native kuicksilver-tls kuicksilver-ktor-network kuicksilver-quic kuicksilver-testing kuicksilver-interop kuicksilver-http3 kuicksilver-ktor-client kuicksilver-ktor-server"
# Modules whose Kotlin/Native tests run on macosArm64 (kuicksilver-interop's native code is the Linux interop executable).
KSL_APPLE_MODULES="kuicksilver-native kuicksilver-tls kuicksilver-ktor-network kuicksilver-quic kuicksilver-testing kuicksilver-http3 kuicksilver-ktor-client kuicksilver-ktor-server"
# Modules whose test executables are linked for Linux, iOS simulator and mingw and run outside Gradle (test.kexe / test.exe).
KSL_LINK_MODULES="kuicksilver-native kuicksilver-quic"

ksl_tasks() { # <task> <modules...> -> ":m1:task :m2:task ..."
  local t="$1" m out=""; shift
  for m in "$@"; do out="$out :$m:$t"; done
  printf '%s\n' "${out# }"
}
# shellcheck disable=SC2086
KSL_JVM_TESTS=$(ksl_tasks jvmTest $KSL_MODULES)
# shellcheck disable=SC2086
KSL_MACOS_TESTS=$(ksl_tasks macosArm64Test $KSL_APPLE_MODULES)
KSL_CHECKS="checkSpdxHeaders checkLayerDependencies checkKotlinAbi"
KSL_ARCH_CHECKS="checkQuicArchitecture checkHttp3Architecture"
KSL_FUZZ_ARGS=(:kuicksilver-quic:jvmTest --tests "io.kuicksilver.quic.fuzz.*" :kuicksilver-http3:jvmTest --tests "io.kuicksilver.http3.fuzz.*")
KSL_SIM_ARGS=(:kuicksilver-testing:jvmTest -Pkuicksilver.sim.runs=200 --tests "io.kuicksilver.testing.MonteCarloTest")

# Runtime image for the linuxArm64 test.kexe: the K/N arm64 sysroot needs glibc 2.25 > manylinux2014 (K1 ruling, task 14).
KSL_UBUNTU_IMAGE="ubuntu:24.04@sha256:534baea6a22c03a63003dbc8dbe78fe34bc0d7e595d9a9dc9834884ff530eb55"

# QUIC Interop Runner (spec 9.4): the full case list for the JVM image, the subset for the Kotlin/Native image, the peers.
KSL_INTEROP_CASES="handshake,transfer,longrtt,chacha20,multiplexing,retry,keyupdate,blackhole,ecn,amplificationlimit,handshakeloss,transferloss,handshakecorruption,transfercorruption,ipv6,v2,rebind-port,rebind-addr,http3"
KSL_INTEROP_NATIVE_CASES="handshake,transfer,retry,keyupdate,ecn,rebind-port,http3"
KSL_INTEROP_PEERS="quic-go ngtcp2 quiche picoquic quinn msquic"
