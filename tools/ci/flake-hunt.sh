#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Reruns the tests of the chosen modules N times under CPU load and summarizes the failures by test.
#
# Usage: tools/ci/flake-hunt.sh [-n runs] [-b burners] [-f forks] [-t jvm|macos] [-T pattern] [-o outdir] [-g gradle] [module...]
#   -n runs     how many times each suite runs (default 20)
#   -b burners  busy-loop processes started for the whole hunt (default: half the CPUs; 0 = no load)
#   -f forks    test JVMs per module running side by side (JVM only, default 2)
#   -t target   jvm (jvmTest, all runs in one build through -Pkuicksilver.test.repeat) or macos (macosArm64Test, one
#               build per run)
#   -T pattern  only the tests matching the pattern (Gradle's --tests; repeatable)
#   -o outdir   where the logs, the result XML of every run and summary.txt go (default build/flake-hunt/<timestamp>)
#   -g gradle   the Gradle command (default ./gradlew; extra Gradle arguments go in FLAKE_HUNT_GRADLE_ARGS)
#   module      Gradle project names, with or without the kuicksilver- prefix (default: http3, quic, http2, ktor-client,
#               ktor-server, ktor-network)
# Exit status: 0 when no test failed, no test process died and every build finished; 1 otherwise; 130 when interrupted.
set -uo pipefail
# -o and -g are taken relative to the caller's directory, the Gradle build runs from the repository root
self="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
root="$(cd "$(dirname "$0")/../.." && pwd)" || exit 2
absolute() { case $1 in /*) echo "$1" ;; *) echo "$PWD/$1" ;; esac; }

runs=20; target=jvm; forks=2; outdir=""; gradle=""
filters=()
cpus=$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)
burners=$((cpus / 2))
while getopts "n:b:f:t:T:o:g:h" opt; do
  case $opt in
    n) runs=$OPTARG ;; b) burners=$OPTARG ;; f) forks=$OPTARG ;; t) target=$OPTARG ;; o) outdir=$(absolute "$OPTARG") ;;
    g) case $OPTARG in */*) gradle=$(absolute "$OPTARG") ;; *) gradle=$OPTARG ;; esac ;; # a bare name is looked up in PATH
    T) filters+=(--tests "$OPTARG") ;;
    *) sed -n '4,17p' "$self"; exit 2 ;;
  esac
done
shift $((OPTIND - 1))
cd "$root" || exit 2
read -r -a extra <<< "${FLAKE_HUNT_GRADLE_ARGS:-}"
gradle=${gradle:-./gradlew}
# one pattern for several modules: a module where it matches nothing must not fail the build
[ ${#filters[@]} -eq 0 ] || extra+=(-Pkuicksilver.test.allowNoMatch)
modules=("$@")
[ ${#modules[@]} -gt 0 ] || modules=(kuicksilver-http3 kuicksilver-quic kuicksilver-http2 kuicksilver-ktor-client kuicksilver-ktor-server kuicksilver-ktor-network)
for i in "${!modules[@]}"; do case ${modules[i]} in kuicksilver-*) ;; *) modules[i]=kuicksilver-${modules[i]} ;; esac; done
case $target in jvm) task=jvmTest ;; macos) task=macosArm64Test ;; *) echo "unknown target $target" >&2; exit 2 ;; esac
outdir=${outdir:-build/flake-hunt/$(date +%Y%m%d-%H%M%S)}
mkdir -p "$outdir"

# The load: plain busy loops that also end by themselves once this script is gone (killed with SIGKILL, say).
pids=()
gradle_pid=""
stop_load() { [ ${#pids[@]} -eq 0 ] || kill "${pids[@]}" 2>/dev/null; pids=(); }
trap stop_load EXIT
# Gradle runs in a process group of its own (below): the whole group, a wrapper such as quiet-gradle and the Gradle client
# under it, gets the TERM; a terminal's Ctrl-C reaches only this script's group
trap '[ -z "$gradle_pid" ] || kill -TERM -- -"$gradle_pid" 2>/dev/null; exit 130' INT TERM
for ((i = 0; i < burners; i++)); do
  (while kill -0 $$ 2>/dev/null; do :; done) &
  pids+=($!)
done
echo "flake-hunt: $runs x $task of ${modules[*]}, $burners CPU burners, results in $outdir"

# Gradle runs in the background so that a signal reaches the trap at once (bash runs a trap only between commands), with
# job control on for the launch: the job gets its own process group, and SIGINT is not ignored in it as in a plain
# background job of a script
run_gradle() {   # run_gradle <log> <args...>
  local log=$1 rc
  shift
  set -m
  "$gradle" "$@" < /dev/null > "$log" 2>&1 & # job control keeps the tty as stdin: a background group reading it would stop
  gradle_pid=$!
  set +m
  wait "$gradle_pid"
  rc=$?
  gradle_pid=""
  return $rc
}

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
  tasks=(); for m in "${modules[@]}"; do tasks+=(":$m:jvmTest" --rerun ${filters[@]+"${filters[@]}"}); done
  run_gradle "$outdir/gradle.log" --continue ${extra[@]+"${extra[@]}"} -Pkuicksilver.test.repeat="$runs" \
    -Pkuicksilver.test.forks="$forks" "${tasks[@]}" || build_failures=1
  collect run-1 jvmTest
  for ((r = 2; r <= runs; r++)); do collect "run-$r" "jvmTestRepeat$r"; done
else
  for ((r = 1; r <= runs; r++)); do
    for m in "${modules[@]}"; do rm -rf "$m/build/test-results/$task"; done
    tasks=(); for m in "${modules[@]}"; do tasks+=(":$m:$task" --rerun ${filters[@]+"${filters[@]}"}); done
    run_gradle "$outdir/gradle-run-$r.log" --continue ${extra[@]+"${extra[@]}"} "${tasks[@]}" || build_failures=$((build_failures + 1))
    collect "run-$r" "$task"
    echo "flake-hunt: run $r of $runs done"
  done
fi
stop_load

# Summary: one line per failed test, "<failures>/<runs it ran in> <class>.<test>", then the first failure message; then
# the test processes that died, from the Gradle logs. Python 3.6 or later.
summary=$outdir/summary.txt
python3 - "$outdir" "$runs" > "$summary" <<'EOF'
import collections, glob, os, re, sys
import xml.etree.ElementTree as ET
out, runs = sys.argv[1], int(sys.argv[2])
ran, failed, first = collections.Counter(), collections.Counter(), {}
missing = []

def strip(name):
    for suffix in ("[jvm]", "[macosArm64]"):  # the first run's names carry the target, the repeats' do not
        if name.endswith(suffix):
            return name[: -len(suffix)]
    return name

for r in range(1, runs + 1):
    files = glob.glob(os.path.join(out, "run-%d" % r, "*", "*.xml"))
    if not files:
        missing.append(r)
    for f in files:
        try:
            root = ET.parse(f).getroot()
        except ET.ParseError:
            failed["(unreadable result) " + os.path.basename(f)] += 1
            continue
        for case in root.iter("testcase"):
            name = strip("%s.%s" % (case.get("classname"), case.get("name")))
            if case.find("skipped") is not None:
                continue
            ran[name] += 1
            bad = case.find("failure")
            if bad is None:
                bad = case.find("error")
            if bad is not None:
                failed[name] += 1
                text = bad.get("message") or bad.get("type") or ""
                first.setdefault(name, "run %d: %s" % (r, text.splitlines()[0][:300] if text else "(no message)"))

# A test process that dies leaves the Gradle log, not the result XML, to say so: a Kotlin/Native executable that ends
# during a test (that test's result is "Unknown") or between two, and a JVM test executor that exits.
died = []
for log in sorted(glob.glob(os.path.join(out, "gradle*.log"))):
    text = open(log, errors="replace").read()
    where = os.path.basename(log)
    for m in re.finditer(r"Execution failed for task '([^']+)'[^\n]*\n> Test running process exited unexpectedly\.(?:\n\s*Current test: (\S+))?", text):
        died.append("%s, %s (%s)" % (m.group(1), "during " + m.group(2) if m.group(2) else "between tests", where))
    for m in re.finditer(r"Execution failed for task '([^']+)'[^\n]*\n> Process '(Gradle Test Executor \d+)' finished with non-zero exit value (\d+)", text):
        died.append("%s, %s exited with %s (%s)" % (m.group(1), m.group(2), m.group(3), where))

print("tests: %d distinct, %d executions over %d runs; failures: %d; test processes died: %d"
      % (len(ran), sum(ran.values()), runs, sum(failed.values()), len(died)))
if missing:
    print("runs with no results at all: %s" % missing)
for name, n in failed.most_common():
    print("%d/%d %s" % (n, ran.get(name, n), name))
    if name in first:
        print("    " + first[name])
for d in died:
    print("test process died: " + d)
EOF
cat "$summary"
if [ "$build_failures" != 0 ]; then echo "flake-hunt: a Gradle build failed, see $outdir/gradle*.log"; fi
if [ "$build_failures" != 0 ] || ! grep -q "failures: 0; test processes died: 0$" "$summary"; then exit 1; fi
