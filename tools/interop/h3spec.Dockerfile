# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# The container tools/interop/h3spec.sh runs the linuxX64 conformance server and h3spec in, together: Debian 13 (h3spec's
# release binary needs glibc 2.34 and libgmp, which the manylinux2014 build image does not have), and h3spec's own
# linux-x86_64 release binary, checked against its sha256 (the version and the digest are tools/interop/h3spec.sh's, passed
# as build arguments; the image is tagged by them and this file's hash). linux/amd64 only: h3spec publishes no
# linux-arm64 binary (an arm64 Mac runs this image under emulation). The server executable is mounted, not copied. The
# base is pinned by digest (the multi-arch index, as tools/check/deployment-guide.Dockerfile).
FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2
ARG H3SPEC_VERSION
ARG H3SPEC_SHA256
RUN test -n "$H3SPEC_VERSION" && test -n "$H3SPEC_SHA256" \
    && apt-get update && apt-get install -y --no-install-recommends curl ca-certificates libgmp10 zlib1g \
    && curl -fsSL -o /usr/local/bin/h3spec "https://github.com/kazu-yamamoto/h3spec/releases/download/$H3SPEC_VERSION/h3spec-linux-x86_64" \
    && echo "$H3SPEC_SHA256  /usr/local/bin/h3spec" | sha256sum -c - \
    && chmod +x /usr/local/bin/h3spec \
    && apt-get purge -y curl && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*
RUN h3spec --version
