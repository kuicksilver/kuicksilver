#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Writes docs/reliability.md from the artifacts that already exist after a gate: the interop matrix of docs/spec/interop.md, the
# fuzz campaign statistics (build/fuzz-campaign/stats.tsv, what `tools/fuzz/campaign.sh status` prints), the soak reports (SoakResult.write(), kuicksilver-soak/build/soak/*.md), the `negative_*` tests in the sources and the
# gate record build/ci/gate/<commit>.stamp. Nothing is run or measured here, nothing is typed by hand into the page, there is no
# network, and the same artifacts always give the same page (no clock, no host name, no absolute path in the output).
# A source that is missing gives "not available" (or "not measured in this gate" / "not sampled by this report" for a table row)
# instead of a number; with --check nothing is written and a missing source is an error (a gate record for a commit other than
# HEAD only warns), so a release cannot publish a page of empty rows.
# Usage: tools/report/reliability.sh [--check] [--stdout] [--out FILE] [--interop FILE] [--fuzz FILE]
#                                    [--soak FILE]... [--gate STAMP-or-DIR] [--src DIR]
#   --soak may be repeated (default: kuicksilver-soak/build/soak/*.md); --gate takes a stamp, or a directory of stamps from
#   which the newest passing one is used (never the record of a run of some steps, --only or --from); --src is the
#   repository whose modules are searched for negative_* tests.
set -euo pipefail
export LC_ALL=C
root="$(cd "$(dirname "$0")/../.." && pwd)"
interop="$root/docs/spec/interop.md"; fuzz="$root/build/fuzz-campaign/stats.tsv"
gate="$root/build/ci/gate"; src="$root"; out="$root/docs/reliability.md"; check=0; soaks=()

die() { echo "reliability.sh: $*" >&2; exit 2; }
while [ $# -gt 0 ]; do
  case "$1" in
    --check) check=1; shift ;;
    --stdout) out=-; shift ;;
    --out|--interop|--fuzz|--gate|--src|--soak)
      [ $# -ge 2 ] || die "$1 needs a value"
      case "$1" in
        --out) out=$2 ;; --interop) interop=$2 ;; --fuzz) fuzz=$2 ;;
        --gate) gate=$2 ;; --src) src=$2 ;; --soak) soaks+=("$2") ;;
      esac
      shift 2 ;;
    -h|--help) sed -n '2,/^set -/p' "$0" | sed '$d; s/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown option $1" ;;
  esac
done
if [ ${#soaks[@]} -eq 0 ]; then
  for f in "$root"/kuicksilver-soak/build/soak/*.md; do [ -f "$f" ] && soaks+=("$f"); done
fi

problems=()
problem() { problems+=("$1"); }

# --- gate record: the newest passing stamp ---
stamp=""
# a run of some steps (tools/ci/local-matrix.sh --only/--from: result=partial-*, a selection other than all) is no gate;
# a record without a selection line is from before selections existed, when every run was a full one
partial() { grep -Eq '^result=partial-' "$1" || { grep -q '^selection=' "$1" && ! grep -qx 'selection=all' "$1"; }; }
if [ -f "$gate" ]; then
  if partial "$gate"; then problem "the gate record ${gate##*/} is of a run that ran only some steps (local-matrix.sh --only/--from), not a gate"
  else stamp=$gate; fi
elif [ -d "$gate" ]; then
  best=""
  for f in "$gate"/*.stamp; do
    [ -f "$f" ] || continue
    grep -qx 'result=pass' "$f" || continue
    partial "$f" && continue
    fin=$(sed -n 's/^finished=//p' "$f" | head -n 1)
    key="$fin $f"
    if [ -z "$best" ] || [[ "$key" > "$best" ]]; then best=$key; fi
  done
  [ -n "$best" ] && stamp=${best#* }
fi
stampval() { sed -n "s/^$1=//p" "$stamp" | head -n 1; }
[ -n "$stamp" ] || problem "no passing gate record at the gate path (build/ci/gate/<commit>.stamp)"

# --- interop ---
matrix_heading=""
if [ -f "$interop" ]; then matrix_heading=$(sed -n 's/^## Interop matrix (\(.*\))$/\1/p' "$interop" | head -n 1); fi
[ -n "$matrix_heading" ] || problem "no interop matrix in the interop file"
# the first matrix section: from its heading to the next "## "
section() { awk '/^## Interop matrix \(/ { if (seen) exit; seen = 1; next } seen && /^## / { exit } seen { print }' "$interop"; }

# --- fuzz ---
fuzz_ok=0
if [ -f "$fuzz" ] && [ -s "$fuzz" ]; then fuzz_ok=1; else problem "no fuzz stats at ${fuzz#"$root"/}"; fi

# --- soak ---
[ ${#soaks[@]} -gt 0 ] || problem "no soak report (kuicksilver-soak/build/soak/*.md)"

# --- negative tests ---
neg_modules=()
if [ -d "$src" ]; then
  for d in "$src"/kuicksilver-*/; do [ -d "${d}src" ] && neg_modules+=("${d%/}"); done
fi
[ ${#neg_modules[@]} -gt 0 ] || problem "no kuicksilver-* modules with sources under the source path"

if [ "$check" = 1 ]; then
  if [ ${#problems[@]} -gt 0 ]; then
    for p in "${problems[@]}"; do echo "reliability.sh: $p" >&2; done
    exit 1
  fi
  if [ -n "$stamp" ]; then
    head=$(git -C "$root" rev-parse HEAD 2>/dev/null || true)
    [ -z "$head" ] || [ "$head" = "$(stampval commit)" ] ||
      echo "reliability.sh: warning: the gate record is for $(stampval commit), HEAD is $head" >&2
  fi
  echo "reliability.sh: all sources present"
  exit 0
fi

count_negative() {  # module dir -> number of negative_* test functions
  find "$1/src" -name '*.kt' -print0 2>/dev/null | xargs -0 grep -hE 'fun +`?negative_' 2>/dev/null | wc -l | tr -d ' ' || true
}

gen() {
cat <<'HDR'
<!--
Copyright 2026 The Kuicksilver Authors
SPDX-License-Identifier: Apache-2.0
-->
<!-- Generated by tools/report/reliability.sh; do not edit -->

# Reliability signals

What the artifacts of the last gate say about reliability: interop against other QUIC stacks, fuzzing time, long soak runs and
the negative tests. Every number below is read from an artifact by `tools/report/reliability.sh`; a row without a source says
"not measured in this gate". These are observations of one gate on one machine, not guarantees; what the API promises is in
[stability.md](stability.md), the method of each check in [process.md](process.md).

## Gate
HDR
echo
if [ -n "$stamp" ]; then
  echo "| | |"; echo "|---|---|"
  echo "| Commit | \`$(stampval commit)\` |"
  echo "| Result | $(stampval result), $(stampval failed) of $(stampval steps) steps failed |"
  echo "| Finished (UTC) | $(stampval finished) |"
  echo "| Host | $(stampval host) |"
  echo "| Interop images | $([ "$(stampval with_interop)" = 1 ] && echo "run in this gate" || echo "not run in this gate (see the matrix below)") |"
  echo "| Windows VM | $([ "$(stampval with_windows)" = 1 ] && echo "run" || echo "not run") |"
  echo
  echo "This is the gate record the page was generated from. The commit that carries the page is a later one, whose own gate runs after the page is written."
else
  echo "Gate record: not available."
fi

echo; echo "## Interop"; echo
if [ -n "$matrix_heading" ]; then
  echo "Latest matrix in [spec/interop.md](spec/interop.md): $matrix_heading. A matrix is a release artifact: it is the run recorded there, not necessarily of the commit above."
  echo
  sec=$(section)
  for img in JVM Native; do
    line=$(grep -m 1 "^$img image" <<< "$sec" || true)
    [ -n "$line" ] || { echo "- $img image: not measured in this gate"; continue; }
    sumtxt=$(sed -n 's/.*[:(] *\([0-9]* of the [0-9]* cells both sides support are green\).*/\1/p' <<< "$line")
    echo "- $img image: ${sumtxt:-no cell summary in the matrix}"
  done
  echo
  # symbols of the first table (the JVM image): one cell is one symbol; ✓¹ counts as green (green on the rerun)
  counts=$(awk '/^\| case \|/ { t = 1; next } t && /^\|---/ { next } t && /^\|/ { g += gsub(/✓/, "&"); r += gsub(/✗/, "&"); q += gsub(/\?/, "&"); next } t { exit } END { print g + 0, r + 0, q + 0 }' <<< "$sec")
  set -- $counts
  echo "First table (JVM image), cells counted from the table: $1 green, $2 red, $3 not supported by one of the sides."
else
  echo "Interop matrix: not available."
fi
echo; echo "## Fuzzing"; echo
if [ "$fuzz_ok" = 1 ]; then
  echo "From \`build/fuzz-campaign/stats.tsv\` (\`tools/fuzz/campaign.sh status\`): one row per target, hours and executions summed over all slices. Findings are slices that ended with anything but \`ok\` or \`load-timeout\`."
  echo
  echo "| Target | Slices | Hours | Executions | Findings |"; echo "|---|---:|---:|---:|---|"
  awk -F'\t' '
    NF >= 8 { id = $2; n[id]++; s[id] += $3; e[id] += $4
      if ($8 != "ok" && $8 != "load-timeout") bad[id] = bad[id] " " $8
      tn++; ts += $3; te += $4; ids[id] = 1 }
    END {
      for (id in ids) order[++k] = id
      for (i = 1; i <= k; i++) for (j = i + 1; j <= k; j++) if (order[j] < order[i]) { x = order[i]; order[i] = order[j]; order[j] = x }
      for (i = 1; i <= k; i++) { id = order[i]; printf "| %s | %d | %.2f | %d | %s |\n", id, n[id], s[id] / 3600, e[id], (bad[id] == "" ? "none" : substr(bad[id], 2)) }
      printf "| **total** | %d | %.2f | %d | |\n", tn, ts / 3600, te
    }' "$fuzz"
  crashes=0
  cdir="$(dirname "$fuzz")/crashes"
  if [ -d "$cdir" ]; then crashes=$(find "$cdir" -type f \( -name 'crash-*' -o -name 'timeout-*' -o -name 'oom-*' \) | wc -l | tr -d ' '); fi
  echo; echo "Reproducer files saved in the campaign's crashes directory, fixed ones included (the artifacts do not say which are open): $crashes."
else
  echo "Fuzz campaign statistics: not available. Fuzzing hours: not measured in this gate."
fi

echo; echo "## Soak"; echo
if [ ${#soaks[@]} -gt 0 ]; then
  echo "From the Markdown reports of \`SoakResult.write()\`. The run line (UTC start and commit) is the report's own; a report from before that line existed says \"not recorded\". The soak is run for a release, not in every gate, so its commit can differ from the gate's. Growth is the Theil–Sen slope over the window after warm-up; a metric is flat while its growth stays within the bound the report lists."
  echo
  echo "| Report | Run (UTC start, commit) | Verdict | Duration | Iterations | Flat metrics | Back to idle baseline |"; echo "|---|---|---|---|---|---:|---:|"
  for f in "${soaks[@]}"; do
    if [ ! -f "$f" ]; then echo "| $(basename "$f") | not available | | | | | |"; continue; fi
    name=$(sed -n 's/^# Soak `\(.*\)`: .*/\1/p' "$f" | head -n 1)
    verdict=$(sed -n 's/^# Soak `.*`: \(.*\)$/\1/p' "$f" | head -n 1)
    run=$(sed -n 's/^Run: \(.*\)\.$/\1/p' "$f" | head -n 1)
    dur=$(sed -n 's/^\(Duration [^,]*, [0-9]* clients\).*/\1/p' "$f" | head -n 1)
    it=$(sed -n 's/^Iterations \([0-9]*\), unexpected failures \([0-9]*\).*/\1 (\2 unexpected)/p' "$f" | head -n 1)
    flat=$(awk '/^## Flatness/ { s = 1; next } /^## / { s = 0 } s && /^\| [a-z]/ { n++; if ($0 ~ /\| flat \|$/) ok++ } END { printf "%d of %d", ok, n }' "$f")
    idle=$(awk '/^## Return to the idle baseline/ { s = 1; next } /^## / { s = 0 } s && /^\| [a-z]/ && !done { n++; if ($0 ~ /\| ok \|$/) ok++ } s && n && /^$/ { done = 1 } END { if (n) printf "%d of %d", ok, n; else printf "not recorded" }' "$f")
    echo "| ${name:-$(basename "$f" .md)} | ${run:-run date/commit: not recorded} | ${verdict:-unknown} | ${dur:-not recorded} | ${it:-not recorded} | $flat | $idle |"
  done
  echo
  echo "Resource trend after warm-up (baseline, median over the window, growth over the window, bound). The coroutine job counts are \`soak.serverJobs\`, \`quic.loopJobs\`, \`server.h3Jobs\` and \`server.tcpJobs\`; a metric the run did not sample is marked so."
  echo
  echo "| Report | Metric | Baseline | Median | Growth | Bound | Verdict |"; echo "|---|---|---:|---:|---:|---:|---|"
  for f in "${soaks[@]}"; do
    [ -f "$f" ] || continue
    name=$(sed -n 's/^# Soak `\(.*\)`: .*/\1/p' "$f" | head -n 1)
    for m in proc.rssKiB proc.fds jvm.heapAfterGcKiB jvm.threads soak.serverJobs quic.loopJobs server.h3Jobs server.tcpJobs; do
      awk -F'|' -v m="$m" -v name="${name:-$(basename "$f" .md)}" '
        /^## Flatness/ { s = 1; next } /^## / { s = 0 }
        s && $2 ~ "^ " m " *$" { for (i = 2; i <= 8; i++) gsub(/^ +| +$/, "", $i)
          printf "| %s | %s | %s | %s | %s | %s | %s |\n", name, $2, $3, $4, $6, $7, $8; found = 1 }
        END { if (!found) printf "| %s | %s | not sampled by this report | | | | |\n", name, m }' "$f"
    done
  done
else
  echo "Soak reports: not available."
fi

echo; echo "## Benchmarks"; echo
echo "Goodput, CPU per GB and handshakes per second are in [benchmarks.md](benchmarks.md); the numbers are not repeated here."

echo; echo "## Negative tests"; echo
echo "Tests named \`negative_*\` (a control that must refuse, not accept), counted in the sources of each module. The list of controls the release gate checks is [section 5 of the threat model](spec/threat-model.md#5-negative-controls--release-gate-checklist)."
echo
if [ ${#neg_modules[@]} -gt 0 ]; then
  echo "| Module | \`negative_*\` tests |"; echo "|---|---:|"
  total=0
  for d in "${neg_modules[@]}"; do
    c=$(count_negative "$d")
    [ "$c" -gt 0 ] || continue
    echo "| $(basename "$d") | $c |"; total=$((total + c))
  done
  echo "| **total** | $total |"
else
  echo "Test sources: not available."
fi
}

if [ "$out" = - ]; then gen
else
  tmp=$(mktemp "${TMPDIR:-/tmp}/reliability.XXXXXX"); trap 'rm -f "$tmp"' EXIT
  gen > "$tmp"
  mkdir -p "$(dirname "$out")"; cat "$tmp" > "$out"
  echo "reliability.sh: wrote ${out#"$root"/}" >&2
fi
