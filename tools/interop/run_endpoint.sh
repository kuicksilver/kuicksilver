#!/bin/bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Entry point inside both interop images: simulator setup, wait for the network, SEC1 -> PKCS#8 key, then the endpoint
# (the Kotlin/Native executable when the image carries one, else the JVM distribution).
set -eu
/setup.sh
if [ "${ROLE:-}" = "client" ]; then /wait-for-it.sh sim:57832 -s -t 30; fi
if [ "${ROLE:-}" = "server" ]; then
  mkdir -p /tmp/certs && cp /certs/cert.pem /tmp/certs/cert.pem
  openssl pkcs8 -topk8 -nocrypt -in /certs/priv.key -out /tmp/certs/priv.key   # the runner's key is SEC1 with an EC PARAMETERS block; kuicksilver-tls imports PKCS#8
  export CERTS=/tmp/certs
fi
if [ -x /app/kuicksilver-interop ]; then exec /app/kuicksilver-interop; fi
case "$(uname -m)" in x86_64) cls=linux-x86_64 ;; aarch64|arm64) cls=linux-aarch_64 ;; *) echo "unsupported arch $(uname -m)" >&2; exit 127 ;; esac
so=$(ls /app/native/$cls/libksl_*.so | sort -t_ -k2,2n | tail -1)   # the highest ABI present
exec java -Dkuicksilver.native.path="$so" ${JAVA_OPTS:-} -cp "/app/lib/*" io.kuicksilver.interop.MainKt
