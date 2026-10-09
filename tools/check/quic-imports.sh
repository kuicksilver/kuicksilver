#!/usr/bin/env bash
# Layer rule for kuicksilver-quic (approved K1 deviation 2): from kuicksilver-native only PacketBuffer and the annotations may be imported.
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
set -uo pipefail
module="${1:-kuicksilver-quic}"; rc=0
while IFS= read -r f; do
  if grep -nE '^import io\.kuicksilver\.native\.' "$f" | grep -vE 'io\.kuicksilver\.native\.(PacketBuffer|of|toByteArray)$' >/dev/null; then
    echo "forbidden kuicksilver-native import: $f"; grep -nE '^import io\.kuicksilver\.native\.' "$f" | grep -vE '(PacketBuffer|of|toByteArray)$' | head -3; rc=1
  fi
done < <(find "$module/src" -path '*/build' -prune -o -path '*Main/*' -name '*.kt' -print)   # main source sets only: tests may load the library
[ $rc -eq 0 ] && echo "quic imports OK"
exit $rc
