# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# QUIC Interop Runner endpoint: Temurin JRE on the simulator base image, the installed distribution and libksl for both Linux arches.
# Pinned by digest (review I8; tag and digest resolved from the registry 2026-10-08). Renovate updates the digest; to pin the image
# a local build already used instead: docker inspect --format "{{index .RepoDigests 0}}" <image>.
FROM martenseemann/quic-network-simulator-endpoint:latest@sha256:3b2b9e6fa317da238c8140a7b6d2bf8d4d45a8464b873eecac3ff2a32520b71a
RUN apt-get update && apt-get install -y --no-install-recommends openjdk-21-jre-headless openssl ca-certificates && rm -rf /var/lib/apt/lists/*
COPY kuicksilver-interop/build/install/kuicksilver-interop /app
COPY kuicksilver-native/build/jni/ /app/native/
COPY tools/interop/run_endpoint.sh /run_endpoint.sh
RUN chmod +x /run_endpoint.sh
ENTRYPOINT ["/run_endpoint.sh"]
