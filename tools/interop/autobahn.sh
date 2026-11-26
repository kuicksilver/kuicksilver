#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# WebSocket conformance of the engines: the Autobahn|Testsuite (crossbario/autobahn-testsuite 25.10.1: every case, 1 to 13,
# RFC 6455 and RFC 7692's permessage-deflate) against the Autobahn server and client of the conformance executable
# (kuicksilver-soak, Autobahn.kt: Ktor's WebSockets plugin with PerMessageDeflate on the engines, over HTTP/1.1):
#   server  the fuzzing client (wstest -m fuzzingclient) against the server engine
#   client  the client engine against the fuzzing server (wstest -m fuzzingserver)
# Every case must pass: Autobahn's verdict OK or INFORMATIONAL for the case and for its closing handshake. Any other
# verdict (NON-STRICT, UNIMPLEMENTED, FAILED, WRONG CODE, UNCLEAN) fails the run, except the cases recorded below as wrong in
# the suite itself, which must get exactly the recorded verdict (a recorded case that passes, or gets another verdict, fails
# the run too). The number of cases must be the one recorded here: a new image that adds or drops cases is noticed.
#   jvm        the JVM server or client on this host, the suite in its container (reaching a server on this host as
#              host.docker.internal on Docker Desktop, 127.0.0.1 with the host network on Linux)
#   macos      the macosArm64 executable on this host (a Mac), the suite in its container
#   linux-x64  the linuxX64 executable inside the suite's own container (one linux/amd64 container per mode: Debian 11,
#              glibc 2.31; the release gate and hosted CI)
# Usage: autobahn.sh [--no-build] [--server|--client] [jvm|macos|linux-x64]...   (default: jvm, both modes); reports in
#        build/autobahn/<kind>-<mode>/ (Autobahn's index.json and per-case files, summary.txt, the line tools/docs/verify.py
#        reads), the list of the runs it makes in build/autobahn/variants.txt
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$root"
# pinned by its registry digest (a single-arch linux/amd64 manifest: the project publishes no other); CI pulls exactly this
# reference (build.yml, linux-native), tools/check/pins.sh refuses an autobahn-testsuite reference without a digest
image="crossbario/autobahn-testsuite:25.10.1@sha256:519915fb568b04c9383f70a1c405ae3ff44ab9e35835b085239c258b6fac3074"
# the number of cases of each mode, first run 2026-11-26 (the fuzzing client and the fuzzing server run the same cases)
expected_cases=517
# The cases whose verdict other than OK is not a departure from RFC 6455 or RFC 7692: "<runs> <cases> <verdicts>" (comma
# lists; a run is a mode, or <kind>:<mode> for one kind only; a verdict is "<behavior>/<behaviorClose>"), each with its
# reason. A recorded case may pass too.
recorded=(
  # A valid message, then (in the same read, or octet by octet in 3.4) a frame that fails the connection: a reserved RSV bit
  # (3.2 to 3.4, RFC 6455 section 5.2), a reserved opcode (4.1.3 to 4.2.5, section 5.2), a continuation with no message to
  # continue (5.15, section 5.4). OK is the echo of the valid message before the Close 1002; NON-STRICT the Close without
  # it. The engine hands Ktor's session a Close 1002 in place of the bad frame, and Ktor's DefaultWebSocketSession answers
  # it from its reading coroutine at once, while the application's echo goes through its writing one: on the server
  # which is written first depends on thread scheduling (both seen on the JVM and on linuxX64); on the client the session
  # also cancels the application's block once both Close frames have passed, before it has read the message, so these
  # cases are NON-STRICT there in every run. Section 7.1.7: the endpoint "SHOULD send a Close frame with an appropriate
  # status code (Section 7.4) before proceeding to _Close the WebSocket Connection_" (1002, in every run); no section asks
  # for an answer to data that came before the violation. NON-STRICT is the suite's own "allowed, not the strictest".
  "server,client 3.2,3.3,3.4,4.1.3,4.1.4,4.1.5,4.2.3,4.2.4,4.2.5,5.15 NON-STRICT/OK"
  # A Ping between the fragments of a message (5.6 to 5.8, 5.19, 5.20): the suite wants each Pong before the echo of a
  # message whose last fragment came after that Ping. Section 5.5.2: "Upon receipt of a Ping frame, an endpoint MUST send a
  # Pong frame in response ... It SHOULD respond with Pong frame as soon as is practical"; section 5.4: control frames "MAY
  # be injected in the middle of a fragmented message". Nothing orders a Pong against the data frames the application
  # sends. Ktor's session queues the Pong as soon as it reads the Ping (its pong coroutine) and the application echoes the
  # message as soon as it has it; the Pong was written right after the echo in some runs (FAILED), before it in others,
  # never late or missing.
  "server,client 5.6,5.7,5.8,5.19,5.20 FAILED/OK"
  # The fuzzing server accepts permessage-deflate in 13.3 to 13.6 only by answering client_max_window_bits (9 or 15),
  # which an offer without that parameter does not allow (RFC 7692 section 7.1.2.2: "If a received extension negotiation
  # offer doesn't have the "client_max_window_bits" extension parameter, the corresponding extension negotiation response
  # to the offer MUST NOT include the "client_max_window_bits" extension parameter"). The client does not offer it: "A
  # client MAY include" it (same section), and the JVM's Deflater, with its fixed 15-bit window, could not keep to a
  # smaller value (PerMessageDeflate). So the suite declines the extension and marks the case UNIMPLEMENTED.
  "client 13.3.1,13.3.2,13.3.3,13.3.4,13.3.5,13.3.6,13.3.7,13.3.8,13.3.9,13.3.10,13.3.11,13.3.12,13.3.13,13.3.14,13.3.15,13.3.16,13.3.17,13.3.18 UNIMPLEMENTED/OK"
  "client 13.4.1,13.4.2,13.4.3,13.4.4,13.4.5,13.4.6,13.4.7,13.4.8,13.4.9,13.4.10,13.4.11,13.4.12,13.4.13,13.4.14,13.4.15,13.4.16,13.4.17,13.4.18 UNIMPLEMENTED/OK"
  "client 13.5.1,13.5.2,13.5.3,13.5.4,13.5.5,13.5.6,13.5.7,13.5.8,13.5.9,13.5.10,13.5.11,13.5.12,13.5.13,13.5.14,13.5.15,13.5.16,13.5.17,13.5.18 UNIMPLEMENTED/OK"
  "client 13.6.1,13.6.2,13.6.3,13.6.4,13.6.5,13.6.6,13.6.7,13.6.8,13.6.9,13.6.10,13.6.11,13.6.12,13.6.13,13.6.14,13.6.15,13.6.16,13.6.17,13.6.18 UNIMPLEMENTED/OK"
  # The fuzzing client offers server_max_window_bits=9 in 13.3 and 13.5. The server accepts an offer "by including the
  # "server_max_window_bits" extension parameter in the extension negotiation response ... with the same or smaller
  # value", and "declines an extension negotiation offer with this parameter if the server doesn't support it" (RFC 7692
  # section 7.1.2.1). On the JVM it declines it: java.util.zip's Deflater has a fixed 15-bit window (PerMessageDeflate,
  # docs/spec/rfc/7692.md); the suite then marks the case UNIMPLEMENTED. Kotlin/Native's zlib keeps to 9: OK there.
  "jvm:server 13.3.1,13.3.2,13.3.3,13.3.4,13.3.5,13.3.6,13.3.7,13.3.8,13.3.9,13.3.10,13.3.11,13.3.12,13.3.13,13.3.14,13.3.15,13.3.16,13.3.17,13.3.18 UNIMPLEMENTED/OK"
  "jvm:server 13.5.1,13.5.2,13.5.3,13.5.4,13.5.5,13.5.6,13.5.7,13.5.8,13.5.9,13.5.10,13.5.11,13.5.12,13.5.13,13.5.14,13.5.15,13.5.16,13.5.17,13.5.18 UNIMPLEMENTED/OK"
)
gradle=${KSL_GRADLE:-./gradlew --max-workers=2}
build=1
specs=()
modes=(server client)
for a in "$@"; do
  case "$a" in
    --no-build) build=0 ;;
    --server) modes=(server) ;;
    --client) modes=(client) ;;
    jvm | macos | linux-x64 | jvm:server | jvm:client | macos:server | macos:client | linux-x64:server | linux-x64:client) specs+=("$a") ;;
    *) echo "usage: autobahn.sh [--no-build] [--server|--client] [jvm|macos|linux-x64][:server|:client]..." >&2; exit 2 ;;
  esac
done
[ ${#specs[@]} -gt 0 ] || specs=(jvm)
# the runs: "<kind> <mode>", a kind without its mode taking the modes of --server / --client (both by default)
runs=()
for spec in "${specs[@]}"; do
  case "$spec" in
    *:*) runs+=("${spec%%:*} ${spec#*:}") ;;
    *) for mode in "${modes[@]}"; do runs+=("$spec $mode"); done ;;
  esac
done

exe() { echo "kuicksilver-soak/build/bin/$1/conformanceDebugExecutable/conformance.kexe"; }
agent=kuicksilver
spec_cases='"cases": ["*"], "exclude-cases": [], "exclude-agent-cases": {}'

# The verdict of one run from Autobahn's index.json: summary.txt gets "<n> tests, <passed> passed, 0 skipped, <failed>
# failed, <recorded> recorded" (the recorded cases with their recorded verdict, counted among the failed).
verdict() { # <kind> <mode> <dir>
  local kind=$1 mode=$2 dir=$3 line
  [ -f "$dir/index.json" ] || { echo "autobahn ($kind $mode): no report; see $dir/" >&2; return 1; }
  line=$(python3 -I - "$dir/index.json" "$agent" "$kind" "$mode" "$expected_cases" ${recorded[@]+"${recorded[@]}"} << 'EOF'
import json, sys
index, agent, kind, mode, expected = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], int(sys.argv[5])
recorded = {}   # case: the verdicts it may get, "<behavior>/<behaviorClose>"
for r in sys.argv[6:]:
    runs, cases, verdicts = r.split()
    if mode in runs.split(",") or f"{kind}:{mode}" in runs.split(","):
        for case in cases.split(","):
            recorded[case] = verdicts.split(",")
cases = json.load(open(index, encoding="utf-8")).get(agent, {})
passing = ("OK", "INFORMATIONAL")
passed = failed = known = 0
bad = []
def order(c):
    return [int(p) for p in c.split(".")]
for case in sorted(cases, key=order):
    got = (cases[case]["behavior"], cases[case]["behaviorClose"])
    if got[0] in passing and got[1] in passing:
        passed += 1
    elif case in recorded:
        failed += 1
        if "/".join(got) in recorded[case]:
            known += 1
        else:
            bad.append(f"{case}: {got[0]} / {got[1]}, recorded as {' or '.join(recorded[case])}")
    else:
        failed += 1
        bad.append(f"{case}: {got[0]} / {got[1]}")
for case in sorted(set(recorded) - set(cases), key=order):
    bad.append(f"{case}: recorded, not run")
print(f"{len(cases)} tests, {passed} passed, 0 skipped, {failed} failed, {known} recorded")
for b in bad:
    print(b, file=sys.stderr)
sys.exit(1 if bad or len(cases) != expected else 0)
EOF
  ) || { [ -n "${line:-}" ] && echo "$line" > "$dir/summary.txt"; echo "autobahn ($kind $mode): ${line:-no verdict}; expected $expected_cases cases, every one OK or INFORMATIONAL but the recorded ones (the reports: $dir/)" >&2; return 1; }
  echo "$line" > "$dir/summary.txt"
  echo "autobahn ($kind $mode): $line"
}

stop_server() { # <pid>: SIGTERM, then SIGKILL (a Kotlin/Native executable may have inherited an ignored SIGTERM)
  kill "$1" 2>/dev/null || true
  for _ in 1 2 3 4 5; do kill -0 "$1" 2>/dev/null || break; sleep 1; done
  kill -KILL "$1" 2>/dev/null || true
  wait "$1" 2>/dev/null || true
}

# The conformance program of a host kind with its arguments.
run_host() { # <kind> <program> <argument>...
  local kind=$1; shift
  case "$kind" in
    jvm) java -cp "kuicksilver-soak/build/install/conformance/lib/*" io.kuicksilver.soak.ConformanceJvmKt "$@" ;;
    macos) "$(exe macosArm64)" "$@" ;;
  esac
}

host_server() { # <kind>: the server on this host, the fuzzing client in its container
  local kind=$1 dir="build/autobahn/$1-server" pid port target=127.0.0.1 net=(--network host)
  mkdir -p "$dir"
  run_host "$kind" autobahn-server 127.0.0.1 0 > "$dir/server.log" 2>&1 &
  pid=$!
  port=""
  for _ in $(seq 1 120); do
    port=$(sed -n 's/^autobahn-server listening on \([0-9]*\)$/\1/p' "$dir/server.log")
    [ -n "$port" ] && break
    kill -0 "$pid" 2>/dev/null || { echo "autobahn ($kind server): the server exited; see $dir/server.log" >&2; return 1; }
    sleep 1
  done
  [ -n "$port" ] || { stop_server "$pid"; echo "autobahn ($kind server): the server did not start within 120 s" >&2; return 1; }
  if [ "$(uname -s)" = Darwin ]; then target=host.docker.internal; net=(); fi
  echo "{\"outdir\": \"/out\", \"servers\": [{\"agent\": \"$agent\", \"url\": \"ws://$target:$port\"}], $spec_cases}" > "$dir/spec.json"
  docker run --rm --platform linux/amd64 ${net[@]+"${net[@]}"} -v "$root/$dir:/out" "$image" \
    wstest -m fuzzingclient -s /out/spec.json > "$dir/wstest.log" 2>&1 || true
  stop_server "$pid"
  verdict "$kind" server "$dir"
}

host_client() { # <kind>: the fuzzing server in its container (a port of this host's loopback), the client on this host
  local kind=$1 dir="build/autobahn/$1-client" cid port rc=0
  mkdir -p "$dir"
  # the fuzzing server refuses a Host whose port is not the one it listens on: the same free port inside and outside
  port=$(python3 -I -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')
  echo "{\"url\": \"ws://0.0.0.0:$port\", \"outdir\": \"/out\", \"webport\": 0, $spec_cases}" > "$dir/spec.json"
  cid=$(docker run -d --rm --platform linux/amd64 -p "127.0.0.1:$port:$port" -v "$root/$dir:/out" "$image" \
    wstest -m fuzzingserver -s /out/spec.json)
  # listening inside the container (Docker Desktop's published port accepts connections before that)
  for _ in $(seq 1 120); do
    docker exec "$cid" bash -c "echo > /dev/tcp/127.0.0.1/$port" 2>/dev/null && break
    sleep 1
  done
  run_host "$kind" autobahn-client 127.0.0.1 "$port" "$agent" > "$dir/client.log" 2>&1 || rc=$?
  docker logs "$cid" > "$dir/wstest.log" 2>&1 || true
  docker stop "$cid" > /dev/null 2>&1 || true
  [ "$rc" = 0 ] || { echo "autobahn ($kind client): the client failed; see $dir/client.log" >&2; return 1; }
  verdict "$kind" client "$dir"
}

linux_run() { # <mode>: the linuxX64 executable and the suite in one container of the suite's image
  local mode=$1 dir="build/autobahn/linux-x64-$1" exe_path user=()
  exe_path=$(exe linuxX64)
  [ -f "$exe_path" ] || { echo "autobahn (linux-x64): missing $exe_path (run without --no-build)" >&2; return 1; }
  mkdir -p "$dir"
  # on a Linux host the container runs as the invoking user, so what it writes into the checkout stays the host's
  [ "$(uname -s)" = Linux ] && user=(--user "$(id -u):$(id -g)" -e HOME=/tmp)
  if [ "$mode" = server ]; then
    docker run --rm ${user[@]+"${user[@]}"} --platform linux/amd64 -v "$root:/w" -w /w --entrypoint bash "$image" -c "
      $exe_path autobahn-server 127.0.0.1 0 > $dir/server.log 2>&1 &
      for i in \$(seq 1 120); do port=\$(sed -n 's/^autobahn-server listening on \\([0-9]*\\)\$/\\1/p' $dir/server.log); [ -n \"\$port\" ] && break; sleep 1; done
      [ -n \"\$port\" ] || { echo 'the server did not start within 120 s'; cat $dir/server.log; exit 1; }
      echo '{\"outdir\": \"$dir\", \"servers\": [{\"agent\": \"$agent\", \"url\": \"ws://127.0.0.1:'\$port'\"}], $spec_cases}' > $dir/spec.json
      wstest -m fuzzingclient -s $dir/spec.json > $dir/wstest.log 2>&1 || true
    " || { echo "autobahn (linux-x64 server): the container run failed" >&2; return 1; }
  else
    docker run --rm ${user[@]+"${user[@]}"} --platform linux/amd64 -v "$root:/w" -w /w --entrypoint bash "$image" -c "
      echo '{\"url\": \"ws://127.0.0.1:9001\", \"outdir\": \"$dir\", \"webport\": 0, $spec_cases}' > $dir/spec.json
      wstest -m fuzzingserver -s $dir/spec.json > $dir/wstest.log 2>&1 &
      for i in \$(seq 1 120); do (echo > /dev/tcp/127.0.0.1/9001) 2>/dev/null && break; sleep 1; done
      $exe_path autobahn-client 127.0.0.1 9001 $agent > $dir/client.log 2>&1
    " || { echo "autobahn (linux-x64 client): the client failed; see $dir/client.log" >&2; return 1; }
  fi
  verdict linux-x64 "$mode" "$dir"
}

# The runs of this invocation, declared before any of them starts (build/autobahn/variants.txt, "<kind> <mode> <report
# directory>" per run, read by tools/docs/verify.py collect --autobahn-manifest); old reports are cleared first.
mkdir -p build/autobahn
manifest=build/autobahn/variants.txt
: > "$manifest"
for run in "${runs[@]}"; do
  read -r kind mode <<< "$run"
  echo "$kind $mode build/autobahn/$kind-$mode" >> "$manifest"
  rm -rf "build/autobahn/$kind-$mode"
done

# No implicit pull in the middle of a gate: the image must be there (docker pull it once).
if ! docker image inspect "$image" > /dev/null 2>&1; then
  echo "autobahn: the image $image is not available locally; pull it first: docker pull --platform linux/amd64 $image" >&2
  exit 1
fi

failed=0
built=" "
for run in "${runs[@]}"; do
  read -r kind mode <<< "$run"
  if [ "$build" = 1 ] && [[ "$built" != *" $kind "* ]]; then
    case "$kind" in
      jvm) $gradle :kuicksilver-soak:installConformance ;;
      macos) $gradle :kuicksilver-soak:linkConformanceDebugExecutableMacosArm64 ;;
      linux-x64) $gradle :kuicksilver-soak:linkConformanceDebugExecutableLinuxX64 ;;
    esac
    built="$built$kind "
  fi
  case "$kind:$mode" in
    linux-x64:*) linux_run "$mode" || failed=1 ;;
    *:server) host_server "$kind" || failed=1 ;;
    *:client) host_client "$kind" || failed=1 ;;
  esac
done
exit $failed
