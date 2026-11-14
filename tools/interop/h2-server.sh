#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# The HTTP/2 server h2spec runs against (tools/interop/h2spec.sh): the Ktor server engine with `http2 = true` on one TLS
# connector (kuicksilver-soak, H2specServer.kt). It prints "h2spec-server listening on <port>" once it accepts connections
# and runs until killed.
# Usage: h2-server.sh build <jvm|macos|linux-x64>       build the server of that kind (Gradle, offline-capable)
#        h2-server.sh run <jvm|macos> [host] [port] [trusted-gateway]
#                                                       run it here (default 127.0.0.1, port 0: any free port; trusted-gateway
#                                                       turns off the misdirected-request check, see H2specServer.kt)
#        h2-server.sh path linux-x64                    print the Linux executable's path (h2spec.sh runs it in a container)
# KSL_GRADLE overrides the Gradle command (default: ./gradlew --max-workers=2).
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$root"
gradle=${KSL_GRADLE:-./gradlew --max-workers=2}
usage() { echo "usage: h2-server.sh build <jvm|macos|linux-x64> | run <jvm|macos> [host] [port] [trusted-gateway] | path linux-x64" >&2; exit 2; }
exe() { echo "kuicksilver-soak/build/bin/$1/h2specServerDebugExecutable/h2spec-server.kexe"; }
[ $# -ge 2 ] || usage
cmd=$1 kind=$2
case "$cmd:$kind" in
  build:jvm) $gradle :kuicksilver-soak:installH2specServer ;;
  build:macos) $gradle :kuicksilver-soak:linkH2specServerDebugExecutableMacosArm64 ;;
  build:linux-x64) $gradle :kuicksilver-soak:linkH2specServerDebugExecutableLinuxX64 ;;
  run:jvm) exec java -cp "kuicksilver-soak/build/install/h2spec-server/lib/*" io.kuicksilver.soak.H2specServerJvmKt "${3:-127.0.0.1}" "${4:-0}" ${5:+"$5"} ;;
  run:macos) exec "$(exe macosArm64)" "${3:-127.0.0.1}" "${4:-0}" ${5:+"$5"} ;;
  path:linux-x64) exe linuxX64 ;;
  *) usage ;;
esac
