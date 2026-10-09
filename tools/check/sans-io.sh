#!/usr/bin/env bash
# Sans-IO rule (ADR-0004): the core packages know nothing about sockets, clocks or coroutines.
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Usage: sans-io.sh [module [base pkg...]]   default: kuicksilver-quic quic wire crypto recovery flow stream core endpoint
set -uo pipefail
module="${1:-kuicksilver-quic}"; rc=0
base="${2:-quic}"
if [ $# -ge 3 ]; then shift 2; pkgs=("$@"); else pkgs=(wire crypto recovery flow stream core endpoint); fi
core="$module/src/commonMain/kotlin/io/kuicksilver/$base"
for pkg in "${pkgs[@]}"; do
  dir="$core/$pkg"; [ -d "$dir" ] || continue
  while IFS= read -r f; do
    # io.ktor.network.sockets.InetSocketAddress is a plain value type (by design: addresses are ktor's); sockets themselves stay out
    pat='(^|[^a-zA-Z])suspend |import kotlinx\.coroutines|import io\.ktor\.network\.(selector|sockets\.(aSocket|Socket|Datagram|Connected|Bound|Server|TcpSocket|UDPSocket))|import io\.ktor\.utils\.io\.(ByteReadChannel|ByteWriteChannel|ByteChannel)|TimeSource|Random\.Default|Clock\.System'
    if grep -nE "$pat" "$f" >/dev/null; then
      echo "sans-IO rule violated: $f"; grep -nE "$pat" "$f" | head -3; rc=1
    fi
  done < <(find "$dir" -name '*.kt')
done
[ $rc -eq 0 ] && echo "sans-IO OK"
exit $rc
