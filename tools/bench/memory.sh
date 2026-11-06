#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# The memory benchmark (kuicksilver-bench MemoryBench, docs/benchmarks.md "Memory"): idle footprint of the process, heap, C
# heap and RSS per idle connection (QUIC core, QUIC endpoints, HTTP/3; both sides, then the server's side alone) and managed-heap
# allocation per GiB moved, on the JVM and on Kotlin/Native. In-process, no Docker: it runs on a busy host; only the udp section
# opens sockets (loopback, the accelerated socket), the others run over a MemoryNetwork or under virtual time.
# Usage: tools/bench/memory.sh [connections] [MiB per transfer] [jvm|native|both]   (defaults: 1000 256 both)
# Each section (core, endpoint, http3, transfer) runs in a process of its own, so one's heap growth is not in the next one's RSS.
# Extra Gradle arguments (e.g. -Pkuicksilver.openssl.prebuilt=true) come from KSL_BENCH_GRADLE_ARGS.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"; cd "$root"
n="${1:-1000}"; mib="${2:-256}"; which="${3:-both}"
gradle=(./gradlew)
[ -x "$HOME/.kuicksilver-tools/quiet-gradle" ] && gradle=("$HOME/.kuicksilver-tools/quiet-gradle")
# shellcheck disable=SC2206
extra=(${KSL_BENCH_GRADLE_ARGS:-})
if [ "$which" != native ]; then
  for s in core endpoint http3 transfer udp; do
    "${gradle[@]}" ${extra[@]+"${extra[@]}"} -q :kuicksilver-bench:jvmMemory -Pkuicksilver.memory.args="$n $mib $s"
  done
fi
if [ "$which" != jvm ]; then
  case "$(uname -s)-$(uname -m)" in
    Darwin-arm64) t=MacosArm64 ;;
    Linux-x86_64) t=LinuxX64 ;;
    *) echo "memory.sh: no Kotlin/Native memory executable for this host"; exit 2 ;;
  esac
  "${gradle[@]}" ${extra[@]+"${extra[@]}"} -q ":kuicksilver-bench:linkMemoryReleaseExecutable$t"
  [ "$t" = MacosArm64 ] && dir=macosArm64 || dir=linuxX64
  for s in core endpoint http3 transfer udp; do "kuicksilver-bench/build/bin/$dir/memoryReleaseExecutable/memory.kexe" "$n" "$mib" "$s"; done
fi
