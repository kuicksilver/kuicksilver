#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# The step selection of tools/ci/local-matrix.sh (--only, --from), through --dry-run only: nothing is built or run. Each
# negative_* case must be refused with exit 2 before the preflight (no "preflight:" line); the others list exactly the
# expected steps. Usage: tools/ci/local-matrix-test.sh
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; script="$here/local-matrix.sh"
fails=0
t() { # <name> <expected exit> <expected listed steps, or a pattern of the refusal> -- <args...>
  local name="$1" want="$2" exp="$3" out rc got; shift 4
  out=$(bash "$script" --dry-run "$@" 2>&1); rc=$?
  if [ "$want" = 0 ]; then got=$(sed -n 's/^\[ *\([0-9]*\)\].*/\1/p' <<< "$out" | tr '\n' ' ' | sed 's/ $//')
    if [ "$rc" = 0 ] && [ "$got" = "$exp" ]; then echo "ok   $name"; else echo "FAIL $name: exit $rc, steps '$got', want '$exp'"; fails=$((fails + 1)); fi
  else
    if [ "$rc" = "$want" ] && grep -qF -- "$exp" <<< "$out" && ! grep -q '^preflight:' <<< "$out" && ! grep -q '^\[' <<< "$out"; then echo "ok   $name"
    else echo "FAIL $name: exit $rc, want $want and '$exp' before any preflight or step"; printf '    %s\n' "$out" | head -5; fails=$((fails + 1)); fi
  fi
}
t onlyListAndRange          0 "25 48 49 52"                          -- --only 25,48-49,52
t onlyLeadingZeros          0 "5 7"                                  -- --only=05,007
t fromWithDependencies      0 "$(seq 44 68 | tr '\n' ' ' | sed 's/ $//')" -- --from 44
t onlyWithItsProducer       0 "38 39"                                -- --only 38,39
t negative_noValue          2 "needs a value"                        -- --only
t negative_optionAsValue    2 "needs a value"                        -- --only --skip-android
t negative_emptyList        2 "an empty step list"                   -- --only ""
t negative_emptyItem        2 "an empty item"                        -- --only 3,,4
t negative_trailingComma    2 "an empty item"                        -- --only 3,
t negative_lineBreak        2 "only digits, commas"                  -- --only $'3\n99'
t negative_injectedLines    2 "only digits, commas"                  -- --only $'3\nresult=pass\nselection=all'
t negative_space            2 "only digits, commas"                  -- --only "3, 4"
t negative_negative         2 "not a step number"                    -- --only -1
t negative_halfRange        2 "not a step number"                    -- --only 3-
t negative_backwards        2 "runs backwards"                       -- --only 5-3
t negative_stepZero         2 "no step 0"                            -- --only 0-3
t negative_pastLast         2 "past the last step"                   -- --only 3,69
t negative_hugeNumber       2 "past the last step"                   -- --only 3-123456789012345678901234
t negative_fromLineBreak    2 "not a step number"                    -- --from $'44\n1'
t negative_fromPastLast     2 "past the last step"                   -- --from 69
t negative_onlyTwice        2 "given twice"                          -- --only 3 --only 4
t negative_onlyAndFrom      2 "together"                             -- --only 3 --from 4
t negative_missingProducer  2 "select those steps too: --only 38,41" -- --only 41
t negative_missingMarkers   2 "select those steps too: --only 58-60" -- --only 60
t negative_fromMissesLink   2 "select those steps too: --only 54,61-68" -- --from 61
[ "$fails" = 0 ] && echo "all passed" || { echo "$fails failed"; exit 1; }
