# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# mingw-w64 cross toolchain: Windows x86_64 native builds.
FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends mingw-w64 perl make binutils llvm && rm -rf /var/lib/apt/lists/*
