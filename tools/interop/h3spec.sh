#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# HTTP/3 and QUIC conformance of the server engine: h3spec (kazu-yamamoto/h3spec v0.1.15: RFC 9000, RFC 9001, RFC 9114 and
# RFC 9204 checks of a server) against the h3spec server of the conformance executable (kuicksilver-soak, H3specServer.kt:
# the Ktor engine with HTTP/3 on one TLS connector, 0-RTT accepted). Every case must pass and none may be pending, except
# the cases recorded below as wrong in h3spec itself, which must fail exactly as recorded (a recorded case that passes,
# or fails another way, fails the run too); the number of cases must be the one recorded here: a new h3spec that adds or
# drops cases is noticed.
# h3spec is the project's release binary, checked against its sha256 before every run:
#   jvm        the JVM server on this host, h3spec's macOS arm64 binary (fetched to build/h3spec/bin/) on this host (a Mac)
#   macos      the macosArm64 executable on this host (a Mac), the same h3spec binary
#   linux-x64  the linuxX64 executable and h3spec's linux-x86_64 binary together in one linux/amd64 container
#              (tools/interop/h3spec.Dockerfile: Debian 13, built here the first time, its apt-get needs the network then;
#              the release gate and hosted CI)
# h3spec reaches the server as 127.0.0.1 in every kind (no Docker network in between): the misdirected-request check stays
# on. h3spec runs with -n (the test PKI's certificate is not validated).
# Usage: h3spec.sh [--no-build] [jvm|macos|linux-x64]...   (default: jvm); reports in build/h3spec/<kind>/ (h3spec.txt,
#        h3spec's output, and summary.txt, the line tools/docs/verify.py reads), the runs it makes in build/h3spec/variants.txt
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$root"
version=v0.1.15
# the sha256 digests GitHub records for the release assets (gh api repos/kazu-yamamoto/h3spec/releases/tags/v0.1.15);
# tools/check/pins.sh refuses a version without them
mac_sha256=a8ca5692abd82ffe09c9f8595b91b87a1700acd6900617b81d8434558006ac32
linux_sha256=c3c5f497153f4ba81f82023791ba7f9a4bc46d4141211e614196f141c5996830
expected_cases=86 # h3spec v0.1.15, first run 2026-11-26: QUIC servers 44 (RFC 9000, RFC 9001), HTTP/3 servers 42 (RFC 9114,
# RFC 9204); a run that reports another count fails here and is to be recorded, not waved through
# The cases h3spec gets wrong, each with the failure it must show: "<case>|<text its failure must contain>".
#   "MUST NOT buffer an over-long frame on a control stream [HTTP/3 7.1]": h3spec sends a GOAWAY frame whose Length is
#   2^30 and expects H3_EXCESSIVE_LOAD (0x107). A GOAWAY carries one variable-length integer, at most 8 bytes (RFC 9114
#   section 7.2.6), so that Length can only mean "a frame payload that contains additional bytes after the identified
#   fields", which RFC 9114 section 7.1 says "MUST be treated as a connection error of type H3_FRAME_ERROR". The server
#   closes with H3_FRAME_ERROR (0x106, 262) from the frame's header, without buffering anything (FrameRules.checkControlLength);
#   H3_EXCESSIVE_LOAD is what it sends for a SETTINGS or PRIORITY_UPDATE frame over its limit, where no Length is malformed.
recorded=(
  "MUST NOT buffer an over-long frame on a control stream [HTTP/3 7.1]|ApplicationProtocolErrorIsReceived (ApplicationProtocolError 262) \"frame 0x7 of 1073741824 bytes holds one integer\""
)
if command -v sha256sum > /dev/null; then sha=(sha256sum); else sha=(shasum -a 256); fi
image="kuicksilver-h3spec:$({ cat tools/interop/h3spec.Dockerfile; echo "$version $linux_sha256"; } | "${sha[@]}" | cut -c1-12)"
gradle=${KSL_GRADLE:-./gradlew --max-workers=2}
build=1
kinds=()
for a in "$@"; do
  case "$a" in
    --no-build) build=0 ;;
    jvm | macos | linux-x64) kinds+=("$a") ;;
    *) echo "usage: h3spec.sh [--no-build] [jvm|macos|linux-x64]..." >&2; exit 2 ;;
  esac
done
[ ${#kinds[@]} -gt 0 ] || kinds=(jvm)

exe() { echo "kuicksilver-soak/build/bin/$1/conformanceDebugExecutable/conformance.kexe"; }

# The verdict of one run from h3spec's output (hspec's: one line per case ending in [✔], [✘] or [‐], then "Failures:" with
# each failure numbered "  N) <group> <case>" and its message, then "<n> examples, <f> failures[, <p> pending]"). Writes
# summary.txt: "<n> tests, <passed> passed, <pending> skipped, <failed> failed, <recorded> recorded" (the failures that are
# recorded above, counted among the failed).
verdict() { # <kind> <dir>
  local out summary total failures pending rc=0 fails=0 known=0 line case text n
  out=$(cat "$2/h3spec.txt")
  summary=$(grep -E '^[0-9]+ examples?, [0-9]+ failures?' <<< "$out" | tail -1 || true)
  if [ -z "$summary" ]; then echo "h3spec ($1): no summary line; see $2/h3spec.txt" >&2; return 1; fi
  total=${summary%% example*}
  failures=$(sed -E 's/^[0-9]+ examples?, ([0-9]+) failures?.*/\1/' <<< "$summary")
  pending=$(sed -nE 's/.*, ([0-9]+) pending.*/\1/p' <<< "$summary"); pending=${pending:-0}
  # each numbered failure: the case after the group name ("QUIC servers" or "HTTP/3 servers")
  while IFS= read -r line; do
    case=$(sed -E 's/^ *[0-9]+\) (QUIC servers|HTTP\/3 servers) //' <<< "$line")
    fails=$((fails + 1))
    local hit=0
    for r in "${recorded[@]}"; do
      [ "${r%%|*}" = "$case" ] || continue
      text=${r#*|}
      # the failure's message: the lines after its numbered line, up to the next blank line
      if awk -v c="$line" 'index($0, c) == 1 { s = 1; next } s && /^$/ { exit } s { print }' <<< "$out" | grep -qF -- "$text"; then
        hit=1; known=$((known + 1))
      else
        echo "h3spec ($1): the recorded case \"$case\" failed another way than recorded" >&2
      fi
    done
    [ "$hit" = 1 ] || rc=1
  done < <(sed -n '/^Failures:/,$p' <<< "$out" | grep -E '^ *[0-9]+\) ')
  for r in "${recorded[@]}"; do
    grep -qF -- "${r%%|*} [✘]" <<< "$out" || { echo "h3spec ($1): the recorded case \"${r%%|*}\" did not fail; remove it from h3spec.sh" >&2; rc=1; }
  done
  n=$((total - fails - pending))
  echo "$total tests, $n passed, $pending skipped, $fails failed, $known recorded" > "$2/summary.txt"
  echo "h3spec ($1): $summary; $known of the failures recorded as h3spec's"
  if [ "$total" != "$expected_cases" ] || [ "$pending" != 0 ] || [ "$fails" != "$failures" ] || [ "$rc" != 0 ] || [ "$known" != "${#recorded[@]}" ]; then
    echo "h3spec ($1): expected $expected_cases cases, all passing but the ${#recorded[@]} recorded, none pending; failures:" >&2
    sed -n '/^Failures:/,$p' <<< "$out" >&2
    return 1
  fi
}

stop_server() { # <pid>: SIGTERM, then SIGKILL (a Kotlin/Native executable may have inherited an ignored SIGTERM)
  kill "$1" 2>/dev/null || true
  for _ in 1 2 3 4 5; do kill -0 "$1" 2>/dev/null || break; sleep 1; done
  kill -KILL "$1" 2>/dev/null || true
  wait "$1" 2>/dev/null || true
}

# h3spec's macOS arm64 binary in build/h3spec/bin/, fetched when missing, checked against its sha256 every time.
host_h3spec() {
  local bin="build/h3spec/bin/h3spec-$version-mac-arm64"
  [ "$(uname -s)-$(uname -m)" = Darwin-arm64 ] || { echo "h3spec: the jvm and macos kinds need a Mac with Apple silicon (h3spec's binary); use linux-x64" >&2; return 1; }
  if [ ! -f "$bin" ]; then
    mkdir -p build/h3spec/bin
    curl -fsSL -o "$bin.part" "https://github.com/kazu-yamamoto/h3spec/releases/download/$version/h3spec-mac-arm64"
    mv "$bin.part" "$bin"
  fi
  [ "$("${sha[@]}" < "$bin" | cut -d' ' -f1)" = "$mac_sha256" ] || { echo "h3spec: $bin does not match its sha256; delete it to fetch it again" >&2; return 1; }
  chmod +x "$bin"
  echo "$bin"
}

host_run() { # <kind>: the server on this host, h3spec beside it
  local kind=$1 dir="build/h3spec/$1" bin pid port
  bin=$(host_h3spec) || return 1
  mkdir -p "$dir"
  case "$kind" in
    jvm) java -cp "kuicksilver-soak/build/install/conformance/lib/*" io.kuicksilver.soak.ConformanceJvmKt h3spec-server 127.0.0.1 0 > "$dir/server.log" 2>&1 & ;;
    macos) "$(exe macosArm64)" h3spec-server 127.0.0.1 0 > "$dir/server.log" 2>&1 & ;;
  esac
  pid=$!
  port=""
  for _ in $(seq 1 120); do
    port=$(sed -n 's/^h3spec-server listening on \([0-9]*\)$/\1/p' "$dir/server.log")
    [ -n "$port" ] && break
    kill -0 "$pid" 2>/dev/null || { echo "h3spec ($kind): the server exited; see $dir/server.log" >&2; return 1; }
    sleep 1
  done
  [ -n "$port" ] || { stop_server "$pid"; echo "h3spec ($kind): the server did not start within 120 s; see $dir/server.log" >&2; return 1; }
  "$bin" 127.0.0.1 "$port" -n > "$dir/h3spec.txt" 2>&1 || true
  stop_server "$pid"
  verdict "$kind" "$dir"
}

linux_run() { # the linuxX64 server and h3spec in one linux/amd64 container
  local dir=build/h3spec/linux-x64 exe_path
  exe_path=$(exe linuxX64)
  [ -f "$exe_path" ] || { echo "h3spec (linux-x64): missing $exe_path (run without --no-build)" >&2; return 1; }
  mkdir -p "$dir"
  if ! docker image inspect "$image" > /dev/null 2>&1; then
    docker build -q --platform linux/amd64 --build-arg "H3SPEC_VERSION=$version" --build-arg "H3SPEC_SHA256=$linux_sha256" \
      -t "$image" -f tools/interop/h3spec.Dockerfile tools/interop > /dev/null
  fi
  # LANG: hspec marks the cases with UTF-8 symbols only in a UTF-8 locale. On a Linux host the container runs as the
  # invoking user, so what it writes into the checkout stays the host's (as tools/ci/docker-run.sh)
  local user=()
  [ "$(uname -s)" = Linux ] && user=(--user "$(id -u):$(id -g)")
  docker run --rm ${user[@]+"${user[@]}"} --platform linux/amd64 -e LANG=C.UTF-8 -v "$root:/w" -w /w "$image" bash -c "
    $exe_path h3spec-server 127.0.0.1 0 > $dir/server.log 2>&1 &
    for i in \$(seq 1 120); do port=\$(sed -n 's/^h3spec-server listening on \\([0-9]*\\)\$/\\1/p' $dir/server.log); [ -n \"\$port\" ] && break; sleep 1; done
    [ -n \"\$port\" ] || { echo 'the server did not start within 120 s'; cat $dir/server.log; exit 1; }
    h3spec 127.0.0.1 \$port -n > $dir/h3spec.txt 2>&1 || true
  " || { echo "h3spec (linux-x64): the container run failed" >&2; return 1; }
  verdict linux-x64 "$dir"
}

# The runs of this invocation, declared before any of them starts (build/h3spec/variants.txt, "<kind> server <report
# directory>" per run, read by tools/docs/verify.py collect --h3spec-manifest); old reports are cleared first.
mkdir -p build/h3spec
manifest=build/h3spec/variants.txt
: > "$manifest"
for kind in "${kinds[@]}"; do
  echo "$kind server build/h3spec/$kind" >> "$manifest"
  rm -f "build/h3spec/$kind/h3spec.txt" "build/h3spec/$kind/summary.txt"
done

failed=0
for kind in "${kinds[@]}"; do
  if [ "$build" = 1 ]; then
    case "$kind" in
      jvm) $gradle :kuicksilver-soak:installConformance ;;
      macos) $gradle :kuicksilver-soak:linkConformanceDebugExecutableMacosArm64 ;;
      linux-x64) $gradle :kuicksilver-soak:linkConformanceDebugExecutableLinuxX64 ;;
    esac
  fi
  case "$kind" in
    linux-x64) linux_run || failed=1 ;;
    *) host_run "$kind" || failed=1 ;;
  esac
done
exit $failed
