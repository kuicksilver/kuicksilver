#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Prepares an Ubuntu 24.04 (noble, amd64) GitHub runner for the QUIC Interop Runner (build.yml's interop job, perf.yml):
#   docker  Docker Engine of the series DOCKER_CE_SERIES from Docker's apt repository (the runner's compose file sets
#           interface_name: Engine 28.1 or later), replacing the runner's moby packages; the repository key must have the
#           fingerprint Docker publishes, docker-ce and docker-ce-cli are installed at the newest version of the series;
#   tshark  tshark from the wireshark-dev/stable PPA (the runner needs 4.5 or later, Ubuntu 24.04 ships 4.2), its signing key
#           fetched by fingerprint from the Ubuntu keyserver and checked against it, plus python3-venv and any further
#           packages given; tshark's version must be 4.5.0 or later.
# Both record what they installed in $GITHUB_STEP_SUMMARY when it is set. Needs sudo, curl, gpg.
# Usage: interop-host.sh docker | tshark [package ...]
set -euo pipefail
DOCKER_CE_SERIES=28                                          # 28.1 or later within it; a new series is a deliberate change here
DOCKER_KEY_FPR=9DC858229FC7DD38854AE2D88D81803C0EBFCD88      # https://docs.docker.com/engine/install/ubuntu/ ("Docker Release (CE deb)")
WIRESHARK_PPA_KEY_FPR=A2E402C42FDD5D1F2D4DB8D4D875551314ECA0F0   # Launchpad PPA for Wireshark Developers (launchpad.net/~wireshark-dev)
summary() { [ -z "${GITHUB_STEP_SUMMARY:-}" ] || printf '%s\n' "$@" >> "$GITHUB_STEP_SUMMARY"; }

# <url> <fingerprint> <keyring>: the key at <url>, refused unless it is exactly the one key <fingerprint>, as a binary keyring
key() {
  local tmp got; tmp=$(mktemp)
  curl -fsSL --retry 3 "$1" -o "$tmp"
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
    sudo apt-get update -q
    v=$(apt-cache madison docker-ce | awk -v s="5:$DOCKER_CE_SERIES." 'index($3, s) == 1 { print $3 }' | sort -V | tail -1)
    [ -n "$v" ] || { echo "::error::Docker's repository has no docker-ce $DOCKER_CE_SERIES.x"; exit 1; }
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -q --allow-downgrades "docker-ce=$v" "docker-ce-cli=$v" containerd.io docker-compose-plugin docker-buildx-plugin
    e=$(docker version --format '{{.Server.Version}}'); echo "after: $e"
    [ "$(printf '%s\n28.1\n' "$e" | sort -V | head -1)" = 28.1 ] || { echo "::error::Docker Engine $e is older than 28.1"; exit 1; }
    summary "Docker Engine $e (docker-ce $v), $(docker compose version --short 2>/dev/null | sed 's/^/compose /'), containerd.io $(dpkg-query -W -f '${Version}' containerd.io)"
    ;;
  tshark)
    shift
    key "https://keyserver.ubuntu.com/pks/lookup?op=get&options=mr&search=0x$WIRESHARK_PPA_KEY_FPR" "$WIRESHARK_PPA_KEY_FPR" /etc/apt/keyrings/wireshark-dev.gpg
    echo "deb [signed-by=/etc/apt/keyrings/wireshark-dev.gpg] https://ppa.launchpadcontent.net/wireshark-dev/stable/ubuntu noble main" | sudo tee /etc/apt/sources.list.d/wireshark-dev.list
    sudo apt-get update -q
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends tshark python3-venv "$@"
    t=$(tshark --version | head -1); echo "$t"
    tv=$(grep -oE '[0-9]+\.[0-9]+\.[0-9]+' <<< "$t" | head -1)
    [ -n "$tv" ] && [ "$(printf '%s\n4.5.0\n' "$tv" | sort -V | head -1)" = 4.5.0 ] || { echo "::error::tshark ${tv:-?} is older than 4.5.0"; exit 1; }
    summary "$t (package $(dpkg-query -W -f '${Version}' tshark), wireshark-dev/stable PPA)"
    ;;
  *) echo "usage: $0 docker | tshark [package ...]" >&2; exit 2 ;;
esac
