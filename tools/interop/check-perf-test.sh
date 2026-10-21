#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Exit-code cases for check-perf.sh on the result files in testdata/ (no runner, no Docker; needs jq).
# Usage: check-perf-test.sh
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; td="$here/testdata"
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
# the thresholds file as blocking, as non-blocking, and with no thresholds at all
jq '.blocking = true' "$here/perf-thresholds.json" > "$tmp/blocking.json"
jq '.blocking = false' "$here/perf-thresholds.json" > "$tmp/advisory.json"
jq '.thresholds = {}' "$here/perf-thresholds.json" > "$tmp/empty.json"
# ngtcp2 with both roles, plus non-object JSON a results directory may hold
mkdir "$tmp/run"; cp "$td/perf-result-sample.json" "$td/perf-result-sample-client.json" "$tmp/run/"
echo '[]' > "$tmp/run/list.json"; echo '42' > "$tmp/run/number.json"
fails=0
case_() {   # name expected-exit [grep pattern] -- check-perf arguments
  local name=$1 want=$2 pat=$3; shift 4
  local got out; out=$(bash "$here/check-perf.sh" "$@" 2>&1); got=$?
  if [ "$got" != "$want" ]; then echo "FAIL $name: exit $got, want $want"; printf '    %s\n' "$out"; fails=$((fails + 1))
  elif [ -n "$pat" ] && ! grep -q -- "$pat" <<< "$out"; then echo "FAIL $name: no '$pat' in"; printf '    %s\n' "$out"; fails=$((fails + 1))
  else echo "ok   $name"; fi
}
case_ "both roles above the floors"           0 "checked 4 cells, 0" -- --expect ngtcp2 "$tmp/run" "$tmp/blocking.json"
case_ "below a floor (blocking)"              1 "REGRESSION"         -- "$td/perf-result-regression.json" "$tmp/blocking.json"
case_ "missing role file (--expect)"          1 "MISSING"            -- --expect ngtcp2 "$td/perf-result-sample.json" "$tmp/blocking.json"
case_ "below a floor (non-blocking)"          0 "non-blocking"       -- "$td/perf-result-regression.json" "$tmp/advisory.json"
case_ "missing role file (non-blocking)"      1 "MISSING"            -- --expect ngtcp2 "$td/perf-result-sample.json" "$tmp/advisory.json"
case_ "without --expect a role is out of scope" 0 "skipped"          -- "$td/perf-result-sample.json" "$tmp/blocking.json"
case_ "no thresholds"                         1 "no threshold"       -- "$tmp/run" "$tmp/empty.json"
# the output is read whole first: check-perf.sh exits 1 here, and under pipefail `check-perf.sh | grep -q` was false
# whatever it printed, so this case could never fail
out=$(bash "$here/check-perf.sh" "$tmp/run" "$tmp/empty.json" 2>&1)
if grep -qE '^[[:space:]]*$' <<< "$out"; then
  echo "FAIL no thresholds: a blank row"; fails=$((fails + 1))
else echo "ok   no thresholds: no blank row"; fi
[ $fails -eq 0 ] && echo "all cases passed"
[ $fails -eq 0 ]
