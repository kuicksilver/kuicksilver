#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# What a SETTINGS acknowledgement held behind DATA (RFC 9113 section 6.5.3) costs an urgent HTTP/2 stream: runs
# HeldAckInversionBench (kuicksilver-http2 jvmTest; a server and a client connection core joined in memory by a link of
# 100 Mbit/s or 1 Gbit/s, virtual time) on this tree and on a base revision, and prints the urgent stream's delays.
# Usage:
#   h2-held-ack.sh [base-rev] [--out DIR]   base-rev defaults to main; DIR to build/bench/h2-held-ack-<date-time>
# The base revision gets the harness copied into a temporary detached worktree (removed afterwards), along with
# local.properties and build/openssl when this tree has them.
# Knobs: KSL_BENCH_GRADLE (default ./gradlew) and KSL_BENCH_GRADLE_ARGS (extra Gradle arguments, e.g. --offline).
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
base=main; out=""
while [ $# -gt 0 ]; do
  case "$1" in
    --out) out=$2; shift 2 ;;
    *) base=$1; shift ;;
  esac
done
out=${out:-$root/build/bench/h2-held-ack-$(date -u +%Y%m%d-%H%M%S)}
mkdir -p "$out"; out=$(cd "$out" && pwd)
gradle=${KSL_BENCH_GRADLE:-./gradlew}
read -r -a gradle_args <<< "${KSL_BENCH_GRADLE_ARGS:-}"
harness=kuicksilver-http2/src/jvmTest/kotlin/io/kuicksilver/http2/core/HeldAckInversionBench.kt
csv="$out/h2-held-ack.csv"
echo "tree,link_mbit,bulk_streams,shrinking,responses,p50_ms,p99_ms,max_ms,acks,ack_p50_ms,ack_p99_ms,ack_max_ms" > "$csv"

measure() { # <tree dir> <label>
  (cd "$1" && KSL_BENCH_H2_HELD_ACK="$csv" KSL_BENCH_H2_HELD_ACK_LABEL="$2" \
    "$gradle" "${gradle_args[@]}" :kuicksilver-http2:jvmTest --tests '*HeldAckInversionBench*' --rerun >"$out/$2.log" 2>&1) ||
    { echo "the $2 run failed: $out/$2.log" >&2; exit 1; }
}

measure "$root" "$(git -C "$root" rev-parse --short HEAD)"
wt="$root/build/bench/h2-held-ack-base"
git -C "$root" worktree remove --force "$wt" 2>/dev/null || true
rm -rf "$wt"; git -C "$root" worktree prune
git -C "$root" worktree add --detach "$wt" "$base" >/dev/null
trap 'git -C "$root" worktree remove --force "$wt" >/dev/null 2>&1 || true; rm -rf "$wt"; git -C "$root" worktree prune' EXIT
mkdir -p "$(dirname "$wt/$harness")"; cp "$root/$harness" "$wt/$harness"
[ -f "$root/local.properties" ] && cp "$root/local.properties" "$wt/"
[ -d "$root/build/openssl" ] && { mkdir -p "$wt/build"; cp -R "$root/build/openssl" "$wt/build/"; }
measure "$wt" "$base@$(git -C "$root" rev-parse --short "$base")"

python3 -I - "$csv" <<'EOF'
import csv, sys
rows = list(csv.DictReader(open(sys.argv[1])))
print("| tree | link | bulk u=7 streams | IWS changes | u=0 responses | p50 ms | p99 ms | max ms | ACK p50 ms | ACK p99 ms | ACK max ms |")
print("|---|---|---|---|---|---|---|---|---|---|---|")
for r in sorted(rows, key=lambda r: (int(r["link_mbit"]), int(r["bulk_streams"]), r["shrinking"], r["tree"])):
    print(f"| {r['tree']} | {r['link_mbit']} Mbit/s | {r['bulk_streams']} | {'every 20 ms' if r['shrinking'] == 'true' else 'none'} "
          f"| {r['responses']} | {r['p50_ms']} | {r['p99_ms']} | {r['max_ms']} | {r['ack_p50_ms'] or '-'} | {r['ack_p99_ms'] or '-'} "
          f"| {r['ack_max_ms'] or '-'} |")
EOF
echo "data: $csv"
