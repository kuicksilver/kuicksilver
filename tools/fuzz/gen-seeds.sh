#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Regenerates the Jazzer seed corpora of kuicksilver-quic and kuicksilver-tls from their deterministic generators:
# kuicksilver-quic/src/jvmTest/kotlin/io/kuicksilver/quic/fuzz/SeedCorpusTest.kt (datagrams of a Null-crypto handshake
# with virtual time and fixed seeds, CVE-style inputs, programs of the stateful connection fuzzer, 0-RTT state) and
# kuicksilver-tls/src/jvmTest/kotlin/io/kuicksilver/tls/fuzz/TlsSeedCorpusTest.kt (hand-built ClientHellos). Seeds are
# named seed-*; reproducers of findings (crash-*) are kept. Without the variable the same tests check that the committed
# corpora match the generators. The grown corpora of local campaigns are in tools/fuzz/corpus (tools/fuzz/campaign.sh).
# Usage: tools/fuzz/gen-seeds.sh
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
gradle() { if [ -x "$HOME/.kuicksilver-tools/quiet-gradle" ]; then (cd "$root" && "$HOME/.kuicksilver-tools/quiet-gradle" "$@"); else "$root/gradlew" -p "$root" --max-workers=2 "$@"; fi; }
for spec in "kuicksilver-quic:io/kuicksilver/quic/fuzz:io.kuicksilver.quic.fuzz.SeedCorpusTest" \
            "kuicksilver-tls:io/kuicksilver/tls/fuzz:io.kuicksilver.tls.fuzz.TlsSeedCorpusTest"; do
  module=${spec%%:*}; rest=${spec#*:}; dir=${rest%%:*}; test=${rest#*:}
  out="$root/$module/src/jvmTest/resources/$dir"
  mkdir -p "$out"
  find "$out" -type f -name 'seed-*' -delete
  KUICKSILVER_FUZZ_SEEDS_OUT="$out" gradle -q ":$module:jvmTest" --tests "$test" --rerun
  echo "seeds: $(find "$out" -type f -name 'seed-*' | wc -l | tr -d ' ') files in ${out#"$root"/}"
done
