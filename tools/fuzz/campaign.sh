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
# Options: --slice MIN (≤ 20, default 20)  --goal HOURS per target (default 2)  --hours HOURS wall clock for this
#          invocation (default: until every selected target reaches the goal)  --gap SEC between slices (default 60)
#          --targets id,id,...  --no-build (reuse the last classpath snapshot)
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
    awk -F'\t' -v id="$id" '$2 == id { n++; s += $3; e += $4; if ($5 > c) c = $5; if ($6 > f) f = $6; corp = $7; if ($8 != "ok" && $8 != "startup-timeout") bad = bad " " $8 }
      END { if (n) printf "%-26s %8d %8.2f %14d %8d %8d %8s  %s\n", id, n, s / 3600, e, c, f, corp, (bad == "" ? "none" : bad) }' "$stats"
  done
  ls "$state"/crashes/*/crash-* "$state"/crashes/*/timeout-* "$state"/crashes/*/oom-* 2>/dev/null | sed 's/^/finding: /' || true
  exit 0
fi

slice=20; goal=2; hours=0; gap=60; only=""; build=1
while [ $# -gt 0 ]; do
  case "$1" in
    --slice) slice=$2; shift 2 ;;
    --goal) goal=$2; shift 2 ;;
    --hours) hours=$2; shift 2 ;;
    --gap) gap=$2; shift 2 ;;
    --targets) only=$2; shift 2 ;;
    --no-build) build=0; shift ;;
    -*) die "unknown option $1" ;;
    *) only="${only:+$only,}$1"; shift ;;
  esac
done
[ "$slice" -ge 1 ] && [ "$slice" -le 20 ] || die "--slice must be 1..20 minutes (the laptop stays quiet)"
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
trap 'rm -rf "$lock"' EXIT INT TERM

quiet() { if command -v taskpolicy >/dev/null 2>&1; then taskpolicy -b nice -n 19 "$@"; else nice -n 19 "$@"; fi; }

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

# One slice of [seconds] on target [id]; appends a line to stats.tsv.
run_slice() {
  local id=$1 secs=$2 kind module cls method corpus seeds committed crashes log start end rc execs cov ft corp result
  kind=$(field "$id" 2); module=$(field "$id" 3); cls=$(field "$id" 4); method=$(field "$id" 5)
  corpus="$state/corpus/$id"; crashes="$state/crashes/$id"; seeds=$(seeds_dir "$id"); committed="$root/tools/fuzz/corpus/$id"
  mkdir -p "$corpus" "$crashes" "$state/logs" "$state/work/$id"
  log="$state/logs/$id-$(date +%Y%m%dT%H%M%S).log"
  local dirs=("$corpus"); [ -d "$seeds" ] && dirs+=("$seeds"); [ -d "$committed" ] && dirs+=("$committed")
  local flags=(-max_total_time="$secs" -timeout=60 -rss_limit_mb=3072 -print_final_stats=1 -artifact_prefix="$crashes/")
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
  cov=$( (grep -Eo 'cov: [0-9]+' "$log" || true) | tail -1 | awk '{ print $2 }')
  ft=$( (grep -Eo 'ft: [0-9]+' "$log" || true) | tail -1 | awk '{ print $2 }')
  corp=$(find "$corpus" -type f | wc -l | tr -d ' ')
  result=ok
  if [ $rc -ne 0 ]; then
    result=$( (ls -t "$crashes" 2>/dev/null | grep -E '^(crash|timeout|oom|slow-unit|leak)-' | head -1) || true)
    [ -n "$result" ] || result="exit-$rc"
    if [ "${result#timeout-}" != "$result" ] && [ "${execs:-0}" -le 1 ]; then
      # the first unit includes loading and instrumenting the classes: on a machine under heavy load that alone can pass
      # -timeout, which is not a finding; the slice is recorded and the target stays in the rotation
      mkdir -p "$state/startup-timeouts"; mv "$crashes/$result" "$state/startup-timeouts/$id-$result"
      result=startup-timeout
      echo "$(date '+%F %T') $id: the first input timed out while loading (machine under load), not a finding"
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
goal_s=$(awk -v h="$goal" 'BEGIN { printf "%d", h * 3600 }')
first=1
while :; do
  next=""; least=-1
  for id in $selected; do
    [ -f "$state/crashed-$id" ] && continue
    t=$(total_seconds "$id"); [ "$t" -ge "$goal_s" ] && continue
    if [ "$least" -lt 0 ] || [ "$t" -lt "$least" ]; then least=$t; next=$id; fi
  done
  [ -n "$next" ] || { echo "every selected target reached ${goal} h (or crashed): done"; break; }
  if [ "$deadline" -ne 0 ]; then
    left=$((deadline - $(date +%s))); [ "$left" -ge 60 ] || { echo "wall clock limit reached"; break; }
  else left=$((slice * 60)); fi
  secs=$((slice * 60)); [ "$secs" -gt "$((goal_s - least))" ] && secs=$((goal_s - least)); [ "$secs" -gt "$left" ] && secs=$left
  [ "$secs" -ge 30 ] || secs=30
  [ "$first" = 1 ] || sleep "$gap"
  first=0
  # new commits (fixes) since the snapshot: rebuild, so a fixed target is not fuzzed on old classes
  if [ "$build" = 1 ] && [ "$(head_rev)" != "$(cat "$state/cp/HEAD" 2>/dev/null)" ]; then
    echo "$(date '+%F %T') HEAD moved: refreshing the classpath snapshot"; snapshot_classpath
  fi
  run_slice "$next" "$secs"
done
"$0" status
