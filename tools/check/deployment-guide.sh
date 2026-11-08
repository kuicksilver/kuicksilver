#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Runs the command block of docs/guide/deployment.md, "Checking a deployment", as it stands in the guide, against the Ktor
# engine as that guide deploys it (kuicksilver-soak DeploymentServer.kt: one TLS connector on port 443, the engine's
# defaults, HTTP/3 on UDP 443), all in one Docker container of the host's architecture (tools/check/deployment-guide.Dockerfile:
# Debian's curl with HTTP/3, tcpdump, sudo). `example.com` resolves to the container's loopback and its certificate is
# issued there by a throwaway CA that curl trusts through CURL_CA_BUNDLE; nothing else of the commands is changed.
# The block's tcpdump commands start first, in the background, for 30 s at most; the other commands then run in order,
# each under `bash -o pipefail`, and each must succeed. Then: the Alt-Svc command printed `h3=":443"`, the
# `curl --http3-only` command got `HTTP/3 200`, and tcpdump saw UDP to port 443. The guide's other blocks change the host
# (sysctl) or start containers themselves (docker run) and do not run here.
# Needs Docker; builds the image kuicksilver-deployment-guide:<Dockerfile hash> the first time and after every change of the
# Dockerfile (its apt-get needs the network then).
# Usage: deployment-guide.sh [--no-build]   (--no-build: the server executable is already linked)
# KSL_GRADLE overrides the Gradle command (default: ./gradlew --max-workers=2). Output in build/deployment-guide/.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$root"
gradle=${KSL_GRADLE:-./gradlew --max-workers=2}
# tagged by the Dockerfile's hash: a changed Dockerfile builds a new image instead of reusing the old one
if command -v sha256sum > /dev/null; then sha=(sha256sum); else sha=(shasum -a 256); fi
image="kuicksilver-deployment-guide:$("${sha[@]}" < tools/check/deployment-guide.Dockerfile | cut -c1-12)"
build=1
for a in "$@"; do
  case "$a" in
    --no-build) build=0 ;;
    *) echo "usage: deployment-guide.sh [--no-build]" >&2; exit 2 ;;
  esac
done
fail() { echo "deployment-guide: $*" >&2; exit 1; }

case "$(docker version -f '{{.Server.Arch}}')" in
  amd64) platform=linux/amd64 target=LinuxX64 dir=linuxX64 ;;
  arm64) platform=linux/arm64 target=LinuxArm64 dir=linuxArm64 ;;
  *) fail "unsupported Docker architecture: $(docker version -f '{{.Server.Arch}}')" ;;
esac
exe="kuicksilver-soak/build/bin/$dir/deploymentServerDebugExecutable/deployment-server.kexe"
# shellcheck disable=SC2086
if [ "$build" = 1 ]; then $gradle -q ":kuicksilver-soak:linkDeploymentServerDebugExecutable$target"; fi
[ -f "$exe" ] || fail "missing $exe (run without --no-build)"

# The block: the first ```sh fence under "## Checking a deployment", up to its closing fence.
guide=docs/guide/deployment.md
block=$(awk '/^## Checking a deployment$/ { s = 1; next } s && /^## / { exit } s && /^```sh$/ { b = 1; next } b && /^```$/ { exit } b { print }' "$guide")
[ -n "$block" ] || fail "$guide: no \`\`\`sh block under \"## Checking a deployment\""
grep -q 'curl --http3-only' <<< "$block" || fail "$guide: the block has no curl --http3-only command"
grep -q 'https://example.com/' <<< "$block" || fail "$guide: the block no longer uses https://example.com/"
grep -q '\\$' <<< "$block" && fail "$guide: a command continued over lines (this script runs one line per command)"

out="build/deployment-guide"
rm -rf "$out"
mkdir -p "$out"
printf '%s\n' "$block" > "$out/commands.sh"
cp "$exe" "$out/deployment-server.kexe"
chmod +x "$out/deployment-server.kexe"

if ! docker image inspect "$image" > /dev/null 2>&1 || [ "$(docker image inspect -f '{{.Architecture}}' "$image")" != "${platform#linux/}" ]; then
  docker build -q --platform "$platform" -t "$image" -f tools/check/deployment-guide.Dockerfile tools/check > /dev/null
fi

# shellcheck disable=SC2016 # expanded in the container
docker run --rm -i --platform "$platform" --add-host example.com:127.0.0.1 -v "$root/$out:/out" "$image" bash -s << 'EOF' || fail "the container run failed; see $out/"
set -euo pipefail
cd /tmp
# a throwaway CA and a certificate for example.com (P-256, PKCS#8 key: what kuicksilver-tls imports)
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 -subj /CN=deployment-guide-ca \
  -keyout ca.key -out ca.pem 2> /dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj /CN=example.com -keyout leaf.key -out leaf.csr 2> /dev/null
printf 'subjectAltName=DNS:example.com\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth\n' > leaf.ext
openssl x509 -req -in leaf.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 2 -extfile leaf.ext -out leaf.pem 2> /dev/null
export CURL_CA_BUNDLE=/tmp/ca.pem

/out/deployment-server.kexe 0.0.0.0 443 leaf.pem leaf.key > /out/server.log 2>&1 &
server=$!
for _ in $(seq 1 60); do
  grep -q '^deployment-server listening on 443$' /out/server.log && break
  kill -0 $server 2> /dev/null || { echo "the server exited:"; cat /out/server.log; exit 1; }
  sleep 1
done
grep -q '^deployment-server listening on 443$' /out/server.log || { echo "the server did not start within 60 s"; cat /out/server.log; exit 1; }

# the tcpdump commands first, in the background and bounded, so they see the curl commands' packets
captures=()
n=0
while IFS= read -r cmd; do
  case "$cmd" in '' | '#'*) continue ;; esac
  n=$((n + 1))
  case "$cmd" in
    *tcpdump*)
      timeout 30 bash -c "$cmd" > "/out/cmd-$n.txt" 2> "/out/cmd-$n.err" &
      captures+=("$!:$n")
      for _ in $(seq 1 50); do grep -q 'listening on' "/out/cmd-$n.err" && break; sleep 0.1; done
      grep -q 'listening on' "/out/cmd-$n.err" || { echo "command $n did not start: $cmd"; cat "/out/cmd-$n.err"; exit 1; }
      ;;
  esac
done < /out/commands.sh
[ ${#captures[@]} -gt 0 ] || { echo "the block has no tcpdump command"; exit 1; }

altsvc=0 h3=0 n=0
while IFS= read -r cmd; do
  case "$cmd" in '' | '#'*) continue ;; esac
  n=$((n + 1))
  case "$cmd" in *tcpdump*) continue ;; esac
  echo "\$ $cmd" | tee -a /out/transcript.txt
  bash -o pipefail -c "$cmd" > "/out/cmd-$n.txt" 2>&1 || { cat "/out/cmd-$n.txt"; echo "command $n failed: $cmd"; exit 1; }
  tee -a /out/transcript.txt < "/out/cmd-$n.txt"
  case "$cmd" in
    *alt-svc*) grep -qi '^alt-svc: h3=":443"' "/out/cmd-$n.txt" && altsvc=1 ;;
    *--http3-only*) head -1 "/out/cmd-$n.txt" | grep -q '^HTTP/3 200' && h3=1 ;;
  esac
done < /out/commands.sh

sleep 1 # tcpdump writes the last packets out
for c in "${captures[@]}"; do kill "${c%%:*}" 2> /dev/null || true; wait "${c%%:*}" 2> /dev/null || true; done
kill $server 2> /dev/null || true
udp=0
for c in "${captures[@]}"; do
  grep -Eq '\.443: UDP' "/out/cmd-${c##*:}.txt" && udp=1
  echo "\$ (tcpdump, command ${c##*:}) $(grep -c 'UDP' "/out/cmd-${c##*:}.txt" || true) UDP packets" | tee -a /out/transcript.txt
done
[ $altsvc = 1 ] || { echo "no Alt-Svc: h3=\":443\" from the Alt-Svc command"; exit 1; }
[ $h3 = 1 ] || { echo "no HTTP/3 200 from the curl --http3-only command"; exit 1; }
[ $udp = 1 ] || { echo "tcpdump saw no UDP to port 443"; exit 1; }
echo "deployment guide commands: Alt-Svc h3=\":443\", HTTP/3 200, UDP 443 captured"
EOF
echo "deployment-guide: OK (transcript in $out/transcript.txt)"
