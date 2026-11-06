#!/usr/bin/env bash
# Reruns the tests of the chosen modules N times under CPU load and summarizes the failures by test.
#
# Usage: tools/ci/flake-hunt.sh [-n runs] [-b burners] [-f forks] [-t jvm|macos] [-o outdir] [-g gradle] [module...]
#   -n runs     how many times each suite runs (default 20)
#   -b burners  busy-loop processes started for the whole hunt (default: half the CPUs; 0 = no load)
#   -f forks    test JVMs per module running side by side (JVM only, default 2)
#   -t target   jvm (jvmTest, all runs in one build through -Pkuicksilver.test.repeat) or macos (macosArm64Test, one
#               build per run)
#   -o outdir   where the logs, the result XML of every run and summary.txt go (default build/flake-hunt/<timestamp>)
#   -g gradle   the Gradle command (default ./gradlew; extra Gradle arguments go in FLAKE_HUNT_GRADLE_ARGS)
#   module      Gradle project names without the colon (default: http3, quic, http2, ktor-client, ktor-server, ktor-network)
# Exit status: 0 when no test failed and every build finished, 1 otherwise.
set -uo pipefail

runs=20; target=jvm; forks=2; outdir=""; gradle=./gradlew
cpus=$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)
burners=$((cpus / 2))
while getopts "n:b:f:t:o:g:h" opt; do
  case $opt in
    n) runs=$OPTARG ;; b) burners=$OPTARG ;; f) forks=$OPTARG ;; t) target=$OPTARG ;; o) outdir=$OPTARG ;; g) gradle=$OPTARG ;;
    *) sed -n '2,13p' "$0"; exit 2 ;;
  esac
done
shift $((OPTIND - 1))
modules=("$@")
[ ${#modules[@]} -gt 0 ] || modules=(kuicksilver-http3 kuicksilver-quic kuicksilver-http2 kuicksilver-ktor-client kuicksilver-ktor-server kuicksilver-ktor-network)
for i in "${!modules[@]}"; do case ${modules[$i]} in kuicksilver-*) ;; *) modules[$i]=kuicksilver-${modules[$i]} ;; esac; done
case $target in jvm) task=jvmTest ;; macos) task=macosArm64Test ;; *) echo "unknown target $target" >&2; exit 2 ;; esac
outdir=${outdir:-build/flake-hunt/$(date +%Y%m%d-%H%M%S)}
mkdir -p "$outdir"
read -r -a extra <<< "${FLAKE_HUNT_GRADLE_ARGS:-}"

# The load: plain busy loops, our own children, stopped on exit.
pids=()
stop_load() { [ ${#pids[@]} -eq 0 ] || kill "${pids[@]}" 2>/dev/null; }
trap stop_load EXIT
trap 'exit 130' INT TERM
for ((i = 0; i < burners; i++)); do (while :; do :; done) & pids+=($!); done
echo "flake-hunt: $runs x $task of ${modules[*]}, $burners CPU burners, results in $outdir"

collect() {   # collect <run label> <results dir name>: copies every module's result XML of that run
  local label=$1 dir=$2 m
  for m in "${modules[@]}"; do
    if [ -d "$m/build/test-results/$dir" ]; then
      mkdir -p "$outdir/$label/$m" && cp "$m"/build/test-results/"$dir"/*.xml "$outdir/$label/$m/" 2>/dev/null
    fi
  done
}

build_failures=0
if [ "$target" = jvm ]; then
  for m in "${modules[@]}"; do rm -rf "$m"/build/test-results/jvmTest "$m"/build/test-results/jvmTestRepeat*; done
  tasks=(); for m in "${modules[@]}"; do tasks+=(":$m:jvmTest" --rerun); done
  "$gradle" --continue ${extra[@]+"${extra[@]}"} -Pkuicksilver.test.repeat="$runs" -Pkuicksilver.test.forks="$forks" "${tasks[@]}" \
    > "$outdir/gradle.log" 2>&1 || build_failures=1
  collect run-1 jvmTest
  for ((r = 2; r <= runs; r++)); do collect "run-$r" "jvmTestRepeat$r"; done
else
  for ((r = 1; r <= runs; r++)); do
    for m in "${modules[@]}"; do rm -rf "$m/build/test-results/$task"; done
    tasks=(); for m in "${modules[@]}"; do tasks+=(":$m:$task" --rerun); done
    if ! "$gradle" --continue ${extra[@]+"${extra[@]}"} "${tasks[@]}" > "$outdir/gradle-run-$r.log" 2>&1; then
      build_failures=$((build_failures + 1))
    fi
    collect "run-$r" "$task"
    echo "flake-hunt: run $r of $runs done"
  done
fi
stop_load

# Summary: one line per failed test, "<failures>/<runs it ran in> <class>.<test>", then the first failure message.
summary=$outdir/summary.txt
python3 - "$outdir" "$runs" > "$summary" <<'EOF'
import collections, glob, os, sys
import xml.etree.ElementTree as ET
out, runs = sys.argv[1], int(sys.argv[2])
ran, failed, first = collections.Counter(), collections.Counter(), {}
missing = []
for r in range(1, runs + 1):
    files = glob.glob(os.path.join(out, f"run-{r}", "*", "*.xml"))
    if not files:
        missing.append(r)
    for f in files:
        try:
            root = ET.parse(f).getroot()
        except ET.ParseError:
            failed[f"(unreadable result) {os.path.basename(f)}"] += 1
            continue
        for case in root.iter("testcase"):
            name = f"{case.get('classname')}.{case.get('name')}".removesuffix("[jvm]").removesuffix("[macosArm64]")
            if case.find("skipped") is not None:
                continue
            ran[name] += 1
            bad = case.find("failure")
            if bad is None:
                bad = case.find("error")
            if bad is not None:
                failed[name] += 1
                first.setdefault(name, f"run {r}: " + (bad.get("message") or bad.get("type") or "").splitlines()[0][:300] if (bad.get("message") or bad.get("type")) else f"run {r}")
# A test process that dies (a Kotlin/Native abort) is reported as a failure of the test that was running ("Unknown"):
# the Gradle log says that the process died, which tells a crash from an assertion.
import re
died = collections.Counter()
for log in sorted(glob.glob(os.path.join(out, "gradle*.log"))):
    text = open(log, errors="replace").read()
    for m in re.finditer(r"Execution failed for task '([^']+)'.*?\n> Test running process exited unexpectedly\.\n\s*Current test: (\S+)", text):
        died[f"{m.group(1)} {m.group(2)} ({os.path.basename(log)})"] += 1
print(f"tests: {len(ran)} distinct, {sum(ran.values())} executions over {runs} runs; failures: {sum(failed.values())}")
if missing:
    print(f"runs with no results at all: {missing}")
for name, n in failed.most_common():
    print(f"{n}/{ran.get(name, n)} {name}")
    if name in first:
        print(f"    {first[name]}")
for name in died:
    print(f"test process died: {name}")
EOF
cat "$summary"
if [ "$build_failures" != 0 ]; then echo "flake-hunt: a Gradle build failed, see $outdir/gradle*.log"; fi
if [ "$build_failures" != 0 ] || ! grep -q "failures: 0$" "$summary"; then exit 1; fi
