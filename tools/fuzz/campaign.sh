#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Local fuzzing campaigns for the Jazzer targets of kuicksilver-tls, kuicksilver-quic and kuicksilver-http3 and the libFuzzer harness of
# ksl (tools/fuzz/ksl/). It replaces the ClusterFuzzLite path for this project: the laptop stays usable, so by default
# every run is a slice of at most 20 minutes at background priority (taskpolicy -b, nice 19, one fuzzing thread, the
# serial collector), with a pause between slices so other builds get the machine. Progress is resumable: the growing
# corpora, per-slice statistics and crash reproducers live in build/fuzz-campaign/ (KSL_FUZZ_STATE), and the next run
# picks the target with the least accumulated time; when HEAD moves (a fix was committed) the classes are rebuilt before
# the next slice. A target that crashed is skipped until build/fuzz-campaign/crashed-<target> is removed (after the fix).
#
# Usage: tools/fuzz/campaign.sh [run] [options]   fuzz in slices
#        tools/fuzz/campaign.sh status            per-target time, executions, coverage, findings
#        tools/fuzz/campaign.sh minimize [ids]     merge the grown corpora into tools/fuzz/corpus/<id>/ (committed)
#        tools/fuzz/campaign.sh list              target ids
# Options: --slice MIN (≤ 20, default 20)  --goal HOURS per target (default 2)  --goals id=HOURS,... (per-target goals
#          that override --goal)  --hours HOURS wall clock for this invocation (default: until every selected target
#          reaches its goal)  --gap SEC between slices (default 60)  --jobs N slices at once, each on its own target
#          (default 1)  --nice N (default 19; background QoS either way)  --targets id,id,...  --no-build (reuse the last
#          classpath snapshot)  --fork N (default 0 = off: libFuzzer/Jazzer -fork=N, N worker processes on the slice's one
#          target, stopping at the first crash, timeout or OOM like a single process; for CI runners, where one job owns
#          the machine: .github/workflows/fuzz.yml)
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
state="${KSL_FUZZ_STATE:-$root/build/fuzz-campaign}"
stats="$state/stats.tsv"
mkdir -p "$state"

# id kind module class method (kind: jvm = Jazzer @FuzzTest, c = tools/fuzz/ksl harness)
targets_table() {
  cat <<'EOF'
quic.frameDecode jvm kuicksilver-quic io.kuicksilver.quic.fuzz.FrameDecodeFuzzTest frameDecode
quic.packetHeader jvm kuicksilver-quic io.kuicksilver.quic.fuzz.PacketHeaderFuzzTest packetHeader
quic.transportParameters jvm kuicksilver-quic io.kuicksilver.quic.fuzz.TransportParametersFuzzTest transportParameters
quic.streamReassembler jvm kuicksilver-quic io.kuicksilver.quic.fuzz.ReassemblerFuzzTest streamReassembler
quic.retryPacket jvm kuicksilver-quic io.kuicksilver.quic.fuzz.RetryPacketFuzzTest retryPacket
quic.endpointRoute jvm kuicksilver-quic io.kuicksilver.quic.fuzz.EndpointRouteFuzzTest endpointRoute
quic.packetRecvServer jvm kuicksilver-quic io.kuicksilver.quic.fuzz.PacketReceiveFuzzTest packetRecvServer
quic.packetRecvClient jvm kuicksilver-quic io.kuicksilver.quic.fuzz.PacketReceiveFuzzTest packetRecvClient
quic.multiPacket jvm kuicksilver-quic io.kuicksilver.quic.fuzz.PacketReceiveFuzzTest multiPacket
quic.postHandshake jvm kuicksilver-quic io.kuicksilver.quic.fuzz.PacketReceiveFuzzTest postHandshake
quic.connectionNull jvm kuicksilver-quic io.kuicksilver.quic.fuzz.ConnectionFuzzTest connectionNull
quic.connectionTls jvm kuicksilver-quic io.kuicksilver.quic.fuzz.ConnectionFuzzTest connectionTls
quic.replayRegister jvm kuicksilver-quic io.kuicksilver.quic.fuzz.ZeroRttFuzzTest replayRegister
quic.rememberedTicket jvm kuicksilver-quic io.kuicksilver.quic.fuzz.ZeroRttFuzzTest rememberedTicket
tls.clientHelloScan jvm kuicksilver-tls io.kuicksilver.tls.fuzz.ZeroRttHelloFuzzTest clientHelloScan
tls.zeroRttHello jvm kuicksilver-tls io.kuicksilver.tls.fuzz.ZeroRttHelloFuzzTest zeroRttHello
http3.h3Frames jvm kuicksilver-http3 io.kuicksilver.http3.fuzz.H3FrameFuzzTest h3Frames
http3.capsules jvm kuicksilver-http3 io.kuicksilver.http3.fuzz.H3FrameFuzzTest capsules
http3.qpackDecode jvm kuicksilver-http3 io.kuicksilver.http3.fuzz.QpackDecodeFuzzTest qpackDecode
ksl.parsers c kuicksilver-native ksl_fuzz parsers
EOF
}

die() { echo "campaign: $*" >&2; exit 2; }
field() { targets_table | awk -v id="$1" -v f="$2" '$1 == id { print $f }'; }
seeds_dir() { # committed seed inputs (Jazzer regression inputs) of a target
  local module cls method; module=$(field "$1" 3); cls=$(field "$1" 4); method=$(field "$1" 5)
  if [ "$(field "$1" 2)" = c ]; then echo "$root/tools/fuzz/ksl/seeds"; return; fi
  local pkg="${cls%.*}"; echo "$root/$module/src/jvmTest/resources/${pkg//.//}/${cls##*.}Inputs/$method"
}
total_seconds() { [ -f "$stats" ] && awk -F'\t' -v id="$1" '$2 == id { s += $3 } END { print s + 0 }' "$stats" || echo 0; }

cmd=run
case "${1:-}" in run|status|minimize|list) cmd=$1; shift ;; esac

if [ "$cmd" = list ]; then targets_table | awk '{ print $1 }'; exit 0; fi

if [ "$cmd" = status ]; then
  [ -f "$stats" ] || { echo "no campaign yet ($stats)"; exit 0; }
  printf '%-26s %8s %8s %14s %8s %8s %8s  %s\n' target slices hours executions cov ft corpus findings
  for id in $(targets_table | awk '{ print $1 }'); do
    awk -F'\t' -v id="$id" '$2 == id { n++; s += $3; e += $4; if ($5 > c) c = $5; if ($6 > f) f = $6; corp = $7; if ($8 != "ok" && $8 != "load-timeout") bad = bad " " $8 }
      END { if (n) printf "%-26s %8d %8.2f %14d %8d %8d %8s  %s\n", id, n, s / 3600, e, c, f, corp, (bad == "" ? "none" : bad) }' "$stats"
  done
  ls "$state"/crashes/*/crash-* "$state"/crashes/*/timeout-* "$state"/crashes/*/oom-* 2>/dev/null | sed 's/^/finding: /' || true
  exit 0
fi

slice=20; goal=2; goals=""; jobs=1; niceness=19; hours=0; gap=60; only=""; build=1; fork=0
while [ $# -gt 0 ]; do
  case "$1" in
    --slice) slice=$2; shift 2 ;;
    --goal) goal=$2; shift 2 ;;
    --goals) goals=$2; shift 2 ;;
    --jobs) jobs=$2; shift 2 ;;
    --nice) niceness=$2; shift 2 ;;
    --hours) hours=$2; shift 2 ;;
    --gap) gap=$2; shift 2 ;;
    --targets) only=$2; shift 2 ;;
    --fork) fork=$2; shift 2 ;;
    --no-build) build=0; shift ;;
    -*) die "unknown option $1" ;;
    *) only="${only:+$only,}$1"; shift ;;
  esac
done
[ "$slice" -ge 1 ] && [ "$slice" -le 20 ] || die "--slice must be 1..20 minutes (the laptop stays quiet)"
[ "$jobs" -ge 1 ] && [ "$jobs" -le 4 ] || die "--jobs must be 1..4"
[ "$niceness" -ge 0 ] && [ "$niceness" -le 20 ] || die "--nice must be 0..20"
[[ "$fork" =~ ^[0-9]+$ ]] && [ "$fork" -le 64 ] || die "--fork must be 0..64"
selected=$(targets_table | awk '{ print $1 }')
if [ -n "$only" ]; then
  for id in ${only//,/ }; do [ -n "$(field "$id" 1)" ] || die "unknown target $id (tools/fuzz/campaign.sh list)"; done
  selected=${only//,/ }
fi

# One campaign at a time, machine-wide.
lock=/tmp/kuicksilver-fuzz-campaign.lock
if ! mkdir "$lock" 2>/dev/null; then
  holder=$(cat "$lock/pid" 2>/dev/null || true)
  if [ -n "$holder" ] && kill -0 "$holder" 2>/dev/null; then die "another campaign is running (pid $holder)"; fi
  rm -rf "$lock"; mkdir "$lock"
fi
echo $$ > "$lock/pid"
trap 'rm -rf "$lock"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

quiet() { if command -v taskpolicy >/dev/null 2>&1; then taskpolicy -b nice -n "$niceness" "$@"; else nice -n "$niceness" "$@"; fi; }

# Classpath snapshot: the project's own class directories and jars are copied, so a rebuild during the campaign does not
# change the classes under a running fuzzer; dependency jars from the Gradle cache are used in place.
head_rev() { git -C "$root" rev-parse HEAD 2>/dev/null || echo none; }
snapshot_classpath() {
  local out="$state/cp" tmp line module entries i dest new
  if [ "$build" = 1 ]; then
    tmp=$(mktemp "$state/cp-print.XXXXXX")
    if [ -x "$HOME/.kuicksilver-tools/quiet-gradle" ]; then
      (cd "$root" && "$HOME/.kuicksilver-tools/quiet-gradle" -q -I tools/fuzz/classpath.init.gradle \
        :kuicksilver-tls:printFuzzClasspath :kuicksilver-quic:printFuzzClasspath :kuicksilver-http3:printFuzzClasspath) > "$tmp"
    else
      (cd "$root" && quiet ./gradlew --max-workers=2 -q -I tools/fuzz/classpath.init.gradle \
        :kuicksilver-tls:printFuzzClasspath :kuicksilver-quic:printFuzzClasspath :kuicksilver-http3:printFuzzClasspath) > "$tmp"
    fi
    rm -rf "$out.new"; mkdir -p "$out.new"
    while IFS= read -r line; do
      case "$line" in "FUZZ_CP "*) ;; *) continue ;; esac
      line=${line#FUZZ_CP }; module=${line%%=*}; entries=${line#*=}
      mkdir -p "$out.new/$module"; i=0; new=""
      for e in ${entries//:/ }; do
        [ -e "$e" ] || continue
        case "$e" in
          "$root"/*) i=$((i + 1)); dest="$out.new/$module/$i-$(basename "$e")"; cp -R "$e" "$dest" ;;
          *) dest=$e ;;
        esac
        new="$new${new:+:}$dest"
      done
      echo "$new" > "$out.new/$module.cp"
    done < "$tmp"
    rm -f "$tmp"
    for m in kuicksilver-tls kuicksilver-quic kuicksilver-http3; do [ -s "$out.new/$m.cp" ] || die "Gradle printed no classpath for $m"; done
    rm -rf "$out"; mv "$out.new" "$out"
    # rewrite the copied paths (they were recorded under cp.new)
    for f in "$out"/*.cp; do sed -i '' -e "s|$out.new/|$out/|g" "$f" 2>/dev/null || sed -i -e "s|$out.new/|$out/|g" "$f"; done
    head_rev > "$out/HEAD"
    [ -x "$root/build/fuzz-ksl/ksl_fuzz" ] && quiet bash "$root/tools/fuzz/ksl/build.sh" >/dev/null || true
  fi
  [ -s "$out/kuicksilver-quic.cp" ] || die "no classpath snapshot: run without --no-build"
}

ksl_harness() { # the ksl harness binary (built by tools/fuzz/ksl/build.sh)
  local bin="$root/build/fuzz-ksl/ksl_fuzz"
  if [ "$build" = 1 ] || [ ! -x "$bin" ]; then quiet bash "$root/tools/fuzz/ksl/build.sh" >/dev/null; fi
  echo "$bin"
}

# True when [input] of target [id] still passes -timeout when run alone (a real hang, not a starved slice).
replay_times_out() {
  local id=$1 input=$2 kind module cls method
  kind=$(field "$id" 2); module=$(field "$id" 3); cls=$(field "$id" 4); method=$(field "$id" 5)
  if [ "$kind" = jvm ]; then
    (cd "$state/work/$id" && quiet java -Xmx1536m -Xss4m -XX:+UseSerialGC -cp "$(cat "$state/cp/$module.cp")" \
      com.code_intelligence.jazzer.Jazzer --target_class="$cls" --target_method="$method" \
      --instrumentation_includes='io.kuicksilver.**' -timeout=60 -runs=3 "$input") > /dev/null 2>&1 && return 1
  else
    (cd "$state/work/$id" && quiet "$(ksl_harness)" -timeout=60 -runs=3 "$input") > /dev/null 2>&1 && return 1
  fi
  return 0
}

# One slice of [seconds] on target [id]; appends a line to stats.tsv.
run_slice() {
  local id=$1 secs=$2 kind module cls method corpus seeds committed crashes log start end rc execs cov ft corp result
  kind=$(field "$id" 2); module=$(field "$id" 3); cls=$(field "$id" 4); method=$(field "$id" 5)
  corpus="$state/corpus/$id"; crashes="$state/crashes/$id"; seeds=$(seeds_dir "$id"); committed="$root/tools/fuzz/corpus/$id"
  mkdir -p "$corpus" "$crashes" "$state/logs" "$state/work/$id"
  log="$state/logs/$id-$(date +%Y%m%dT%H%M%S).log"
  local dirs=("$corpus"); [ -d "$seeds" ] && dirs+=("$seeds"); [ -d "$committed" ] && dirs+=("$committed")
  local flags=(-max_total_time="$secs" -timeout=60 -rss_limit_mb=3072 -print_final_stats=1 -artifact_prefix="$crashes/")
  # fork mode ignores timeouts and OOMs by default and goes on; here it stops on them, so a finding ends the slice as before
  [ "$fork" -gt 0 ] && flags+=(-fork="$fork" -ignore_crashes=0 -ignore_timeouts=0 -ignore_ooms=0)
  echo "$(date '+%F %T') $id: slice of ${secs}s (log ${log#"$root"/})"
  start=$(date +%s); set +e
  if [ "$kind" = jvm ]; then
    (cd "$state/work/$id" && quiet java -Xmx1536m -Xss4m -XX:+UseSerialGC -XX:CICompilerCount=2 -Djava.awt.headless=true \
      -cp "$(cat "$state/cp/$module.cp")" com.code_intelligence.jazzer.Jazzer \
      --target_class="$cls" --target_method="$method" --instrumentation_includes='io.kuicksilver.**' \
      --reproducer_path="$crashes" "${flags[@]}" "${dirs[@]}") > "$log" 2>&1
  else
    (cd "$state/work/$id" && quiet "$(ksl_harness)" "${flags[@]}" "${dirs[@]}") > "$log" 2>&1
  fi
  rc=$?; set -e; end=$(date +%s)
  # a log without a match must not end the campaign (set -e with pipefail)
  execs=$(sed -n 's/^Done \([0-9]*\) runs in.*/\1/p' "$log" | tail -1)
  [ -n "$execs" ] || execs=$(sed -n 's/^stat::number_of_executed_units: *\([0-9]*\).*/\1/p' "$log" | tail -1)
  [ -n "$execs" ] || execs=$(sed -n 's/^#\([0-9]*\): cov: .*/\1/p' "$log" | tail -1)   # fork mode: "#<total runs>: cov: ..."
  cov=$( (grep -Eo 'cov: [0-9]+' "$log" || true) | tail -1 | awk '{ print $2 }')
  ft=$( (grep -Eo 'ft: [0-9]+' "$log" || true) | tail -1 | awk '{ print $2 }')
  corp=$(find "$corpus" -type f | wc -l | tr -d ' ')
  result=ok
  if [ $rc -ne 0 ]; then
    result=$( (ls -t "$crashes" 2>/dev/null | grep -E '^(crash|timeout|oom|leak)-' | head -1) || true)
    [ -n "$result" ] || result="exit-$rc"
    if [ "${result#timeout-}" != "$result" ] && ! replay_times_out "$id" "$crashes/$result"; then
      # at background priority on a machine under heavy load a unit can be starved past -timeout (the first one also loads
      # and instruments the classes): a timeout whose input runs in time when replayed is not a finding; the slice is
      # recorded and the target stays in the rotation
      mkdir -p "$state/load-timeouts"; mv "$crashes/$result" "$state/load-timeouts/$id-$result"
      rm -f "$crashes/slow-unit-${result#timeout-}"
      result=load-timeout
      echo "$(date '+%F %T') $id: a timeout that does not reproduce (machine under load), not a finding"
    else
      echo "$id" > "$state/crashed-$id"
      echo "$(date '+%F %T') $id: FINDING $result (log ${log#"$root"/})"
    fi
  fi
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$(date '+%FT%T')" "$id" "$((end - start))" "${execs:-0}" "${cov:-0}" "${ft:-0}" "$corp" "$result" >> "$stats"
}

if [ "$cmd" = minimize ]; then
  snapshot_classpath
  for id in $selected; do
    corpus="$state/corpus/$id"; [ -d "$corpus" ] || continue
    kind=$(field "$id" 2); module=$(field "$id" 3); cls=$(field "$id" 4); method=$(field "$id" 5)
    seeds=$(seeds_dir "$id"); committed="$root/tools/fuzz/corpus/$id"; out="$state/merge/$id"
    rm -rf "$out"; mkdir -p "$out/min" "$committed"
    # the committed seeds go in first, so the merged set keeps only inputs that add coverage beyond them; then they are removed
    [ -d "$seeds" ] && for f in "$seeds"/*; do [ -f "$f" ] && cp "$f" "$out/min/seed-baseline-$(basename "$f")"; done
    if [ "$kind" = jvm ]; then
      (cd "$state/work/$id" 2>/dev/null || cd "$state"; quiet java -Xmx1536m -Xss4m -XX:+UseSerialGC -cp "$(cat "$state/cp/$module.cp")" \
        com.code_intelligence.jazzer.Jazzer --target_class="$cls" --target_method="$method" \
        --instrumentation_includes='io.kuicksilver.**' -merge=1 -timeout=60 -rss_limit_mb=3072 "$out/min" "$committed" "$corpus") \
        > "$out/merge.log" 2>&1 || { echo "$id: merge failed (see $out/merge.log)"; continue; }
    else
      quiet "$(ksl_harness)" -merge=1 "$out/min" "$committed" "$corpus" > "$out/merge.log" 2>&1 || { echo "$id: merge failed"; continue; }
    fi
    rm -f "$out/min"/seed-baseline-*
    rm -rf "$committed"; mkdir -p "$committed"; cp "$out/min"/* "$committed"/ 2>/dev/null || true
    echo "$id: $(find "$corpus" -type f | wc -l | tr -d ' ') grown inputs -> $(find "$committed" -type f | wc -l | tr -d ' ') in tools/fuzz/corpus/$id"
  done
  exit 0
fi

snapshot_classpath
deadline=0; [ "$hours" != 0 ] && deadline=$(( $(date +%s) + $(awk -v h="$hours" 'BEGIN { printf "%d", h * 3600 }') ))
goal_of() { # seconds of fuzzing [id] should get
  local h=$goal g
  for g in ${goals//,/ }; do [ "${g%%=*}" = "$1" ] && h=${g#*=}; done
  awk -v h="$h" 'BEGIN { printf "%d", h * 3600 }'
}
# running slices: parallel arrays (bash 3.2 has no associative arrays and no wait -n)
run_pids=(); run_ids=(); run_secs=()
reap() {
  local i np=() ni=() ns=()
  for i in "${!run_pids[@]}"; do
    if kill -0 "${run_pids[$i]}" 2>/dev/null; then np+=("${run_pids[$i]}"); ni+=("${run_ids[$i]}"); ns+=("${run_secs[$i]}")
    else wait "${run_pids[$i]}" 2>/dev/null || true; fi
  done
  run_pids=(${np[@]+"${np[@]}"}); run_ids=(${ni[@]+"${ni[@]}"}); run_secs=(${ns[@]+"${ns[@]}"})
}
running() { local i; for i in ${run_ids[@]+"${run_ids[@]}"}; do [ "$i" = "$1" ] && return 0; done; return 1; }
kill_tree() { # [pid] and its descendants, by PID
  local c
  for c in $(ps -ax -o pid= -o ppid= | awk -v p="$1" '$2 == p { print $1 }'); do kill_tree "$c"; done
  kill "$1" 2>/dev/null || true
}
# INT/TERM only exit (128+signal); the EXIT trap does the cleanup, exactly once
cleanup() { for p in ${run_pids[@]+"${run_pids[@]}"}; do kill_tree "$p"; done; rm -rf "$lock"; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
first=1; stop=""
while :; do
  reap
  if [ -n "$stop" ]; then [ "${#run_pids[@]}" -eq 0 ] && { echo "$stop"; break; }; sleep 5; continue; fi
  if [ "${#run_pids[@]}" -ge "$jobs" ]; then sleep 5; continue; fi
  # the target furthest from its goal (smallest share of it done), not already running
  next=""; best=""; left_goal=0
  for id in $selected; do
    [ -f "$state/crashed-$id" ] && continue
    running "$id" && continue
    t=$(total_seconds "$id"); g=$(goal_of "$id"); [ "$t" -ge "$g" ] && continue
    share=$(awk -v t="$t" -v g="$g" 'BEGIN { printf "%.6f", t / g }')
    if [ -z "$best" ] || awk -v a="$share" -v b="$best" 'BEGIN { exit !(a < b) }'; then best=$share; next=$id; left_goal=$((g - t)); fi
  done
  if [ -z "$next" ]; then
    [ "${#run_pids[@]}" -eq 0 ] && { echo "every selected target reached its goal (or crashed): done"; break; }
    sleep 5; continue
  fi
  if [ "$deadline" -ne 0 ]; then
    left=$((deadline - $(date +%s))); [ "$left" -ge 60 ] || { stop="wall clock limit reached"; continue; }
  else left=$((slice * 60)); fi
  secs=$((slice * 60)); [ "$secs" -gt "$left_goal" ] && secs=$left_goal; [ "$secs" -gt "$left" ] && secs=$left
  [ "$secs" -ge 30 ] || secs=30
  [ "$first" = 1 ] || sleep "$gap"
  first=0
  # new commits (fixes) since the snapshot: rebuild once no slice runs, so a fixed target is not fuzzed on old classes
  # and no running fuzzer has its classes or binary replaced under it
  if [ "$build" = 1 ] && [ "$(head_rev)" != "$(cat "$state/cp/HEAD" 2>/dev/null)" ]; then
    if [ "${#run_pids[@]}" -gt 0 ]; then sleep 5; continue; fi
    echo "$(date '+%F %T') HEAD moved: refreshing the classpath snapshot"; snapshot_classpath
  fi
  run_slice "$next" "$secs" &
  run_pids+=($!); run_ids+=("$next"); run_secs+=("$secs")
done
"$0" status
