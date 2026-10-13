// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
// The unprefixed OpenSSL side of the collision probe (bridging header of the CollisionProbe target).
#ifndef KSL_COLLISION_PROBE_H
#define KSL_COLLISION_PROBE_H

/// A complete TLS 1.3 handshake between two SSL objects of the UNPREFIXED OpenSSL over a memory BIO pair, with a
/// throwaway self-signed P-256 certificate. Returns 0 on success and writes "<version> <protocol> <cipher>" to out.
int probe_unprefixed_openssl_handshake(char *out, int out_len);

#endif
