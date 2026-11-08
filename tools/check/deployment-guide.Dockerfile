# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# The container tools/check/deployment-guide.sh runs docs/guide/deployment.md's commands in: Debian 13, whose curl is built
# with HTTP/3 (OpenSSL QUIC and nghttp3; `curl -V` lists HTTP3), tcpdump, sudo and openssl (the test certificate). The server
# executable is mounted, not copied. Pinned by digest (the multi-arch index, resolved from the registry 2026-11-08).
FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2
RUN apt-get update && apt-get install -y --no-install-recommends curl tcpdump sudo openssl ca-certificates procps \
    && rm -rf /var/lib/apt/lists/*
RUN curl -V | grep -q '^Features:.* HTTP3' || { echo "this curl has no HTTP/3" >&2; exit 1; }
# as the guide's Docker section has it
EXPOSE 443/tcp 443/udp
