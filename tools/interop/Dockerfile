# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# QUIC Interop Runner endpoint: Temurin JRE on the simulator base image, the installed distribution and libksl for both Linux arches.
FROM martenseemann/quic-network-simulator-endpoint:latest
RUN apt-get update && apt-get install -y --no-install-recommends openjdk-21-jre-headless openssl ca-certificates && rm -rf /var/lib/apt/lists/*
COPY kuicksilver-interop/build/install/kuicksilver-interop /app
COPY kuicksilver-native/build/jni/ /app/native/
COPY tools/interop/run_endpoint.sh /run_endpoint.sh
RUN chmod +x /run_endpoint.sh
ENTRYPOINT ["/run_endpoint.sh"]
