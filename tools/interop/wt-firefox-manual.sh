#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# One-command by-hand WebTransport check in Firefox against the Ktor server (docs/guide/ktor.md, "WebTransport").
# Usage: tools/interop/wt-firefox-manual.sh
# It makes a temporary directory with a P-256 certificate valid for 13 days (CN and SAN localhost, SAN IP 127.0.0.1;
# serverCertificateHashes takes only such a short-lived, non-RSA certificate) and its base64 SHA-256 hash, starts
# ManualWebTransportServer (kuicksilver-ktor-server jvmTest, through ~/.kuicksilver-tools/quiet-gradle) on 127.0.0.1, and
# once it listens opens https://localhost:<port>/wt/index.html?hash=<hash> in Firefox with a throw-away profile. Accept
# Firefox's certificate warning for the page once ("Advanced", "Accept the Risk and Continue"): the hash covers only the
# WebTransport sessions, not the page. The page runs its steps and posts the result; the script prints PASS or FAIL with
# the page's JSON, stops Firefox and the Gradle run it started (only those, by process group) and removes the directory.
# Env: FIREFOX (the firefox executable; default: Firefox.app in /Applications or ~/Applications), WT_PORT (default 0: the
# server picks a free port), WT_HOST (the host in the URL, default localhost; 127.0.0.1 also matches the certificate),
# WT_TIMEOUT (seconds to wait for the page's result, default 600), OPENSSL (default: openssl on PATH; LibreSSL works too),
# KSL_GRADLE (default ~/.kuicksilver-tools/quiet-gradle, ./gradlew where that is missing), WT_KEEP=1 keeps the directory.
# Exit 0 on PASS, 1 on FAIL, 2 when something needed is missing.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$root"

host="${WT_HOST:-localhost}"
port="${WT_PORT:-0}"
timeout="${WT_TIMEOUT:-600}"
openssl="${OPENSSL:-openssl}"
gradle="${KSL_GRADLE:-$HOME/.kuicksilver-tools/quiet-gradle}"
[ -x "$gradle" ] || gradle="./gradlew"

firefox="${FIREFOX:-}"
if [ -z "$firefox" ]; then
  for app in /Applications/Firefox.app "$HOME/Applications/Firefox.app" "/Applications/Firefox Developer Edition.app" \
    "/Applications/Firefox Nightly.app"; do
    if [ -x "$app/Contents/MacOS/firefox" ]; then firefox="$app/Contents/MacOS/firefox"; break; fi
  done
  [ -n "$firefox" ] || firefox="$(command -v firefox || true)"
fi
if [ -z "$firefox" ] || [ ! -x "$firefox" ]; then
  echo "wt-firefox-manual: no Firefox found; set FIREFOX=<path to the firefox executable>" >&2
  exit 2
fi
command -v "$openssl" >/dev/null || { echo "wt-firefox-manual: $openssl not found; set OPENSSL" >&2; exit 2; }
version="$("$firefox" --version 2>/dev/null || echo "$firefox")"   # prints the version; opens no window

tmp="$(mktemp -d "${TMPDIR:-/tmp}/kuicksilver-wt-firefox.XXXXXX")"
gradle_pid=""
firefox_pid=""

# Each background job below runs in its own process group (set -m), so a stop reaches the job's children too (gradlew's
# JVM under quiet-gradle, Firefox's helpers) and nothing else; Ctrl-C at the terminal reaches only this script's group,
# whose INT trap then stops them. The Gradle daemon is not in the group: it cancels the build when its client goes.
# shellcheck disable=SC2329   # called from cleanup, the EXIT trap
stop_group() {
  local pid="$1"
  [ -n "$pid" ] || return 0
  kill -0 "$pid" 2>/dev/null || return 0
  kill -TERM -- "-$pid" 2>/dev/null || kill -TERM "$pid" 2>/dev/null || true
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    kill -0 "$pid" 2>/dev/null || return 0
    sleep 1
  done
  kill -KILL -- "-$pid" 2>/dev/null || kill -KILL "$pid" 2>/dev/null || true
}
# shellcheck disable=SC2329   # the EXIT trap
cleanup() {
  local rc=$?
  trap - EXIT INT TERM
  stop_group "$firefox_pid"
  stop_group "$gradle_pid"
  if [ "${WT_KEEP:-}" = 1 ]; then echo "wt-firefox-manual: kept $tmp"; else rm -rf "$tmp"; fi
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# the certificate: P-256, 13 days, an end-entity certificate for localhost and 127.0.0.1
cat >"$tmp/cert.cnf" <<'EOF'
[req]
distinguished_name = dn
prompt = no
[dn]
CN = localhost
[v3]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = DNS:localhost, IP:127.0.0.1
EOF
"$openssl" genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$tmp/wt.key" 2>/dev/null
"$openssl" req -new -x509 -key "$tmp/wt.key" -sha256 -days 13 -config "$tmp/cert.cnf" -extensions v3 -out "$tmp/wt.pem"
hash="$("$openssl" x509 -in "$tmp/wt.pem" -outform der | "$openssl" dgst -sha256 -binary | base64)"
# the query value, percent-encoded: base64 has '+', '/' and '='
qhash="${hash//+/%2B}"
qhash="${qhash//\//%2F}"
qhash="${qhash//=/%3D}"

echo "wt-firefox-manual: starting the server through $gradle (the first build can take a few minutes)"
set -m
"$gradle" --console=plain :kuicksilver-ktor-server:jvmTest \
  --tests 'io.kuicksilver.ktor.server.browser.ManualWebTransportServer' --rerun \
  -Pkuicksilver.manualWebTransport=true \
  "-Pkuicksilver.manualWebTransport.cert=$tmp/wt.pem" \
  "-Pkuicksilver.manualWebTransport.key=$tmp/wt.key" \
  "-Pkuicksilver.manualWebTransport.port=$port" \
  "-Pkuicksilver.manualWebTransport.dir=$tmp" \
  "-Pkuicksilver.manualWebTransport.timeoutSeconds=$timeout" \
  >"$tmp/gradle.log" 2>&1 &
gradle_pid=$!
set +m

# compiling may wait for a quiet-gradle slot and then build: give it up to 30 minutes to listen
waited=0
while [ ! -f "$tmp/ready" ]; do
  if ! kill -0 "$gradle_pid" 2>/dev/null; then
    echo "wt-firefox-manual: FAIL: Gradle ended before the server listened; the end of its output:" >&2
    tail -n 60 "$tmp/gradle.log" >&2
    exit 1
  fi
  if [ "$waited" -ge 1800 ]; then
    echo "wt-firefox-manual: FAIL: the server did not listen within 30 minutes; the end of Gradle's output:" >&2
    tail -n 60 "$tmp/gradle.log" >&2
    exit 1
  fi
  sleep 1
  waited=$((waited + 1))
done
bound="$(head -n 1 "$tmp/ready")"
url="https://$host:$bound/wt/index.html?hash=$qhash"

# A throw-away profile. HTTP/3 and WebTransport are on by default in current Firefox; the prefs keep them on whatever
# the defaults become, keep HTTP/3 on when the system has extra root certificates (Firefox turns HTTP/3 off then), and
# make localhost resolve to 127.0.0.1 only (the server does not listen on ::1). The rest keeps first-run pages and
# prompts out of the way.
profile="$tmp/profile"
mkdir -p "$profile"
cat >"$profile/user.js" <<'EOF'
user_pref("network.http.http3.enable", true);
user_pref("network.webtransport.enabled", true);
user_pref("network.http.http3.disable_when_third_party_roots_found", false);
user_pref("security.enterprise_roots.enabled", false);
user_pref("security.certerrors.mitm.auto_enable_enterprise_roots", false);
user_pref("network.dns.disableIPv6", true);
user_pref("network.proxy.type", 0);
user_pref("browser.shell.checkDefaultBrowser", false);
user_pref("browser.aboutwelcome.enabled", false);
user_pref("browser.startup.homepage_override.mstone", "ignore");
user_pref("startup.homepage_welcome_url", "");
user_pref("startup.homepage_welcome_url.additional", "");
user_pref("datareporting.policy.dataSubmissionEnabled", false);
user_pref("toolkit.telemetry.reportingpolicy.firstRun", false);
user_pref("app.update.disabledForTesting", true);
EOF

echo "wt-firefox-manual: server on 127.0.0.1:$bound; opening Firefox at"
echo "  $url"
echo "wt-firefox-manual: accept Firefox's certificate warning once (Advanced, Accept the Risk and Continue);"
echo "  the page then runs its steps by itself. Waiting up to $timeout s for its result (Ctrl-C stops everything)."
set -m
"$firefox" -no-remote -profile "$profile" "$url" >"$tmp/firefox.log" 2>&1 &
firefox_pid=$!
set +m

gradle_rc=0
wait "$gradle_pid" || gradle_rc=$?
gradle_pid=""

echo
if [ -f "$tmp/result.json" ]; then
  echo "Page result: $(cat "$tmp/result.json")"
  cat "$tmp/server.txt" 2>/dev/null || true
fi
if [ "$gradle_rc" -eq 0 ] && [ -f "$tmp/result.json" ]; then
  echo "wt-firefox-manual: PASS: every step ok in $version"
  exit 0
fi
if [ -f "$tmp/result.json" ]; then
  echo "wt-firefox-manual: FAIL: the page or the server saw a step fail; the end of Gradle's output:" >&2
else
  echo "wt-firefox-manual: FAIL: no result from the page (the server stopped waiting after $timeout s or failed); the end of Gradle's output:" >&2
fi
tail -n 60 "$tmp/gradle.log" >&2
exit 1
