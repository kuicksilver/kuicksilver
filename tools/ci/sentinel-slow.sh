#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Sourced by docker-run.sh and docker-jvm.sh: the leak sentinel's slow-teardown bound (KUICKSILVER_LEAK_SLOW_MS) for a
# container. A container of another architecture than the host runs emulated (linux/amd64 on an Apple Silicon Mac), where
# a QUIC connection's closing period (3 x PTO, RFC 9000 section 10.2) grows with the slower round trips: 6 connections took
# 1636 ms to close there (ContentTest.testEmptyContent, 2026-11-20), over the default 1500 ms, while no teardown in the native
# linux-arm64 run reached it. An emulated run gets KSL_EMULATED_LEAK_SLOW_MS (6000, about 3.7 times that) unless the caller set
# KUICKSILVER_LEAK_SLOW_MS; a native one keeps the sentinel's default.
#   sentinel_slow_for <docker-platform> [host-machine]   sets and exports KUICKSILVER_LEAK_SLOW_MS for an emulated platform
#   arch_of <docker-platform | uname -m>             amd64, arm64, or the input when unknown

arch_of() {
  case "${1##*/}" in
    x86_64 | amd64) echo amd64 ;;
    aarch64 | arm64) echo arm64 ;;
    *) echo "${1##*/}" ;;
  esac
}

sentinel_slow_for() {
  local plat="$1" host="${2:-$(uname -m)}"
  local want="${plat#*/}"; want="${want%%/*}"
  [ -n "${KUICKSILVER_LEAK_SLOW_MS:-}" ] && return 0
  [ "$(arch_of "$want")" = "$(arch_of "$host")" ] && return 0
  export KUICKSILVER_LEAK_SLOW_MS="${KSL_EMULATED_LEAK_SLOW_MS:-6000}"
}
