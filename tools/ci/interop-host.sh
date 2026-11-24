#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Prepares an Ubuntu 24.04 (noble, amd64) GitHub runner for the QUIC Interop Runner (build.yml's interop job, perf.yml):
#   docker  Docker Engine of the series DOCKER_CE_SERIES from Docker's apt repository (the runner's compose file sets
#           interface_name: Engine 28.1 or later), replacing the runner's moby packages; the repository key must have the
#           fingerprint Docker publishes, docker-ce and docker-ce-cli are installed at the newest version of the series;
#   tshark  tshark from the wireshark-dev/stable PPA (the runner needs 4.5 or later, Ubuntu 24.04 ships 4.2), its signing key
#           fetched by fingerprint from the Ubuntu keyserver and checked against it, plus python3-venv and any further
#           packages given; tshark's version must be 4.5.0 or later. The PPA (ppa.launchpadcontent.net) answers 503 for hours at
#           a time; apt-get update reports a source it could not fetch only as a warning and exits 0, and the install then takes
#           Ubuntu's tshark 4.2 (seven interop jobs: four apt exits 100, three "tshark 4.2.2 is older than 4.5.0"). So the
#           candidate must be 4.5.0 or later before anything is installed, the install names that exact version, and update and
#           install are tried again with a doubling pause (KSL_INTEROP_APT_ATTEMPTS, default 5; KSL_INTEROP_APT_DELAY, the first
#           pause in seconds, default 30: about 7.5 minutes in all). There is no fallback: no other source of tshark 4.5 or
#           later is pinned and verified (Ubuntu 24.04's archive has 4.2, which cannot follow a peer's new connection ID), so a
#           PPA that stays down fails the step with a message that says so.
# Both record what they installed in $GITHUB_STEP_SUMMARY when it is set. Needs sudo, curl, gpg.
# Usage: interop-host.sh docker | tshark [package ...]   (tools/ci/interop-host-test.sh tests the tshark retries with stubs)
set -euo pipefail
DOCKER_CE_SERIES=28                                          # 28.1 or later within it; a new series is a deliberate change here
DOCKER_KEY_FPR=9DC858229FC7DD38854AE2D88D81803C0EBFCD88      # https://docs.docker.com/engine/install/ubuntu/ ("Docker Release (CE deb)")
WIRESHARK_PPA_KEY_FPR=A2E402B85A4B70CD78D8A3D9D875551314ECA0F0   # signing_key_fingerprint of ~wireshark-dev/+archive/ubuntu/stable (Launchpad API)
summary() { [ -z "${GITHUB_STEP_SUMMARY:-}" ] || printf '%s\n' "$@" >> "$GITHUB_STEP_SUMMARY"; }
# every network fetch retries, refused connections and failed name lookups too (curl's plain --retry covers only HTTP-level and
# timeout errors; keyserver.ubuntu.com fails with refused connections from time to time)
apt_get() { sudo DEBIAN_FRONTEND=noninteractive apt-get -o Acquire::Retries=5 "$@"; }

# <url> <fingerprint> <keyring>: the key at <url>, refused unless it is exactly the one key <fingerprint>, as a binary keyring
key() {
  local tmp got; tmp=$(mktemp)
  curl -fsSL --retry 5 --retry-all-errors --retry-delay 5 "$1" -o "$tmp"
  got=$(gpg --show-keys --with-colons "$tmp" 2>/dev/null | awk -F: '$1 == "pub" { want = 1 } $1 == "fpr" && want { print $10; want = 0 }')
  if [ "$got" != "$2" ]; then echo "::error::the key from $1 has the fingerprint(s) '${got//$'\n'/ }', not $2"; rm -f "$tmp"; exit 1; fi
  sudo install -m 0755 -d /etc/apt/keyrings
  gpg --dearmor < "$tmp" | sudo tee "$3" > /dev/null; sudo chmod 0644 "$3"; rm -f "$tmp"
}

case "${1:-}" in
  docker)
    docker version --format 'before: {{.Server.Version}}' || true
    sudo apt-get remove -y -q moby-engine moby-cli moby-buildx moby-compose moby-containerd moby-runc || true
    key https://download.docker.com/linux/ubuntu/gpg "$DOCKER_KEY_FPR" /etc/apt/keyrings/docker.gpg
    echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu noble stable" | sudo tee /etc/apt/sources.list.d/docker.list
    apt_get update -q
    v=$(apt-cache madison docker-ce | awk -v s="5:$DOCKER_CE_SERIES." 'index($3, s) == 1 { print $3 }' | sort -V | tail -1)
    [ -n "$v" ] || { echo "::error::Docker's repository has no docker-ce $DOCKER_CE_SERIES.x"; exit 1; }
    apt_get install -y -q --allow-downgrades "docker-ce=$v" "docker-ce-cli=$v" containerd.io docker-compose-plugin docker-buildx-plugin
    e=$(docker version --format '{{.Server.Version}}'); echo "after: $e"
    [ "$(printf '%s\n28.1\n' "$e" | sort -V | head -1)" = 28.1 ] || { echo "::error::Docker Engine $e is older than 28.1"; exit 1; }
    summary "Docker Engine $e (docker-ce $v), $(docker compose version --short 2>/dev/null | sed 's/^/compose /'), containerd.io $(dpkg-query -W -f '${Version}' containerd.io)"
    ;;
  tshark)
    shift
    key "https://keyserver.ubuntu.com/pks/lookup?op=get&options=mr&search=0x$WIRESHARK_PPA_KEY_FPR" "$WIRESHARK_PPA_KEY_FPR" /etc/apt/keyrings/wireshark-dev.gpg
    echo "deb [signed-by=/etc/apt/keyrings/wireshark-dev.gpg] https://ppa.launchpadcontent.net/wireshark-dev/stable/ubuntu noble main" | sudo tee /etc/apt/sources.list.d/wireshark-dev.list
    attempts=${KSL_INTEROP_APT_ATTEMPTS:-5}; pause=${KSL_INTEROP_APT_DELAY:-30}; n=1
    while :; do
      why=""
      if ! apt_get update -q; then
        why="apt-get update failed"
      elif ! cand=$(apt-cache policy tshark | awk '$1 == "Candidate:" { print $2 }'); then
        why="apt-cache policy tshark failed"   # under set -e this would end the script without a word
      else
        cv=${cand#*:}; cv=${cv%%-*}   # the upstream version of [epoch:]upstream[-revision]
        if [ -z "$cand" ] || [ "$cand" = "(none)" ] || [ "$(printf '%s\n4.5.0\n' "$cv" | sort -V | head -1)" != 4.5.0 ]; then
          why="the tshark candidate is ${cand:-none}, not 4.5.0 or later: the PPA's index was not fetched"
        elif ! apt_get install -y -q --no-install-recommends "tshark=$cand" python3-venv "$@"; then
          why="apt-get install of tshark $cand failed"
        else
          break
        fi
      fi
      if [ "$n" -ge "$attempts" ]; then
        echo "::error::tshark 4.5.0 or later could not be installed from the wireshark-dev/stable PPA in $attempts attempts ($why). The PPA (ppa.launchpadcontent.net) is probably down: re-run the job later. Ubuntu's tshark 4.2 is not installed in its place: it cannot follow a peer's new connection ID, which turns the keyupdate and rebind cells red."
        exit 1
      fi
      echo "::warning::attempt $n of $attempts: $why; trying again in ${pause}s"
      sleep "$pause"; n=$((n + 1)); pause=$((pause * 2))
    done
    t=$(tshark --version | head -1); echo "$t"
    tv=$(grep -oE '[0-9]+\.[0-9]+\.[0-9]+' <<< "$t" | head -1)
    [ -n "$tv" ] && [ "$(printf '%s\n4.5.0\n' "$tv" | sort -V | head -1)" = 4.5.0 ] || { echo "::error::tshark ${tv:-?} is older than 4.5.0"; exit 1; }
    summary "$t (package $(dpkg-query -W -f '${Version}' tshark), wireshark-dev/stable PPA)"
    ;;
  *) echo "usage: $0 docker | tshark [package ...]" >&2; exit 2 ;;
esac
