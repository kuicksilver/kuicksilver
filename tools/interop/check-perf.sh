#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Checks QUIC Interop Runner measurements (goodput, crosstraffic) against minimum goodput thresholds.
# Usage: check-perf.sh [--update] <result>[,<result>...] [thresholds.json]   (default: tools/interop/perf-thresholds.json)
#   <result> is a runner result file (run.py -j) or a directory of them (run-local.sh writes <peer>-{server,client}.json).
# The runner stores, per cell, {"name", "abbr", "result", "details": "<mean> (± <stdev>) kbps"} over its 5 repetitions in
# "measurements"[client index * len(servers) + server index] (interop.py _export_results). A threshold is in scope when
# its server/client pair and its measurement took part in the given results; an in-scope cell that is missing,
# not "succeeded" or below min_kbps is a regression (exit 1), and so is a run with no threshold in scope at all.
# Cells measured in several given results (a rerun) count with their best succeeded mean.
# --update prints the thresholds file with min_kbps/recorded_kbps proposed from the given results (mean x (1 - tolerance),
# rounded down to 100 kbps; tolerances from the file); review it and write it back by hand.
set -euo pipefail
update=0
[ "${1:-}" = "--update" ] && { update=1; shift; }
[ $# -ge 1 ] && [ $# -le 2 ] || { sed -n '4,5p' "$0" | sed 's/^# //' >&2; exit 2; }
thr="${2:-$(cd "$(dirname "$0")" && pwd)/perf-thresholds.json}"
command -v jq >/dev/null || { echo "check-perf: jq is required" >&2; exit 2; }
[ -f "$thr" ] || { echo "check-perf: no thresholds file $thr" >&2; exit 2; }
files=()
IFS=, read -r -a inputs <<< "$1"
for i in "${inputs[@]}"; do
  if [ -d "$i" ]; then for f in "$i"/*.json; do [ -f "$f" ] && files+=("$f"); done
  elif [ -f "$i" ]; then files+=("$i")
  else echo "check-perf: no such result file or directory: $i" >&2; exit 2; fi
done
[ ${#files[@]} -gt 0 ] || { echo "check-perf: no result files in $1" >&2; exit 2; }

# One entry per measured cell: {key, result, mean, sd}; the best succeeded entry wins when a cell appears more than once.
cells=$(jq -s '
  [ .[] | select(type == "object" and has("measurements")) | . as $r
    | ($r.servers | length) as $ns
    | range(0; $r.clients | length) as $ci | range(0; $ns) as $si
    | ($r.measurements[$ci * $ns + $si] // [])[]
    | { key: "\($r.servers[$si])->\($r.clients[$ci]):\(.name)", result,
        mean: ([(.details // "") | capture("^(?<m>[0-9.]+)") | .m | tonumber] | first),
        sd: ([(.details // "") | capture("\\(± (?<s>[0-9.]+)\\)") | .s | tonumber] | first) } ]
  | group_by(.key)
  | map(sort_by(if .result == "succeeded" then (.mean // 0) else -1 end) | last)' "${files[@]}")
# What these results could have produced: their server->client pairs and the measurements they asked for.
scope=$(jq -s '{ pairs: ([ .[] | . as $r | ($r.servers // [])[] as $s | ($r.clients // [])[] as $c | "\($s)->\($c)" ] | unique),
                 cases: ([ .[] | (.tests // {}) | to_entries[] | .value.name ] | unique) }' "${files[@]}")

if [ $update -eq 1 ]; then
  jq --argjson cells "$cells" '
    .tolerance as $tol
    | .thresholds += ([ $cells[] | select(.result == "succeeded" and .mean != null)
        | (.key | split(":")[1]) as $m | select($tol[$m] != null)
        | { key, value: { min_kbps: ((.mean * (1 - $tol[$m]) / 100 | floor) * 100), recorded_kbps: (.mean | round) } } ]
      | from_entries)' "$thr"
  exit 0
fi

rows=$(jq -r --argjson cells "$cells" --argjson scope "$scope" '
  ($cells | map({ (.key): . }) | add // {}) as $by
  | .thresholds | to_entries[]
  | (.key | split(":")) as [$ep, $case]
  | if ($scope.pairs | index([$ep])) and ($scope.cases | index([$case])) then
      $by[.key] as $c
      | [ .key, (.value.min_kbps | tostring),
          (if $c == null then "-" elif $c.mean == null then "-" else "\($c.mean | round) ± \($c.sd // 0 | round)" end),
          (if $c == null then "MISSING" elif $c.result != "succeeded" then ($c.result | ascii_upcase)
           elif $c.mean == null then "UNPARSED" elif $c.mean < .value.min_kbps then "REGRESSION" else "ok" end) ]
    else [ .key, (.value.min_kbps | tostring), "-", "skipped" ] end
  | @tsv' "$thr")

fmt='%-36s %10s %16s  %s\n'
# shellcheck disable=SC2059   # the format string is ours
printf "$fmt" "cell (server->client:measurement)" "min kbps" "measured kbps" "status"
checked=0; bad=0
while IFS=$'\t' read -r key min measured status; do
  # shellcheck disable=SC2059
  printf "$fmt" "$key" "$min" "$measured" "$status"
  case "$status" in skipped) ;; ok) checked=$((checked + 1)) ;; *) checked=$((checked + 1)); bad=$((bad + 1)) ;; esac
done <<< "$rows"
if [ $checked -eq 0 ]; then echo "check-perf: no threshold of $thr is in scope of the given results" >&2; exit 1; fi
echo "checked $checked cells, $bad below threshold or not measured"
[ $bad -eq 0 ]
