# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# mingw-w64 cross toolchain: Windows x86_64 native builds.
# Pinned by digest (review I8; tag and digest resolved from the registry 2026-10-08). Renovate updates the digest; to pin the image
# a local build already used instead: docker inspect --format "{{index .RepoDigests 0}}" <image>.
FROM ubuntu:24.04@sha256:534baea6a22c03a63003dbc8dbe78fe34bc0d7e595d9a9dc9834884ff530eb55
RUN apt-get update && apt-get install -y --no-install-recommends mingw-w64 perl make binutils llvm && rm -rf /var/lib/apt/lists/*
