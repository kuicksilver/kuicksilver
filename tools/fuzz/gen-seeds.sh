#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Regenerates the Jazzer seed corpus of kuicksilver-quic from the deterministic generator in
# kuicksilver-quic/src/jvmTest/kotlin/io/kuicksilver/quic/fuzz/SeedCorpusTest.kt: datagrams of a Null-crypto handshake
# (virtual time, fixed seeds) plus CVE-style inputs. Seeds are named seed-*; reproducers of findings (crash-*) are kept.
# Without the variable the same test checks that the committed corpus matches the generator.
# Usage: tools/fuzz/gen-seeds.sh
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
out="$root/kuicksilver-quic/src/jvmTest/resources/io/kuicksilver/quic/fuzz"
mkdir -p "$out"
find "$out" -type f -name 'seed-*' -delete
KUICKSILVER_FUZZ_SEEDS_OUT="$out" "$root/gradlew" -p "$root" --max-workers=2 -q \
  :kuicksilver-quic:jvmTest --tests 'io.kuicksilver.quic.fuzz.SeedCorpusTest' --rerun
echo "seeds: $(find "$out" -type f -name 'seed-*' | wc -l | tr -d ' ') files in ${out#"$root"/}"
