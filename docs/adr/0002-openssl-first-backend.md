# ADR-0002. OpenSSL 3.5 is the first TLS backend; BoringSSL is the fallback; the transport depends on the `QuicCrypto` interface

Date: 2026-10-02. Status: accepted (approved by the owner 2026-10-02).

## Context

OpenSSL 3.5 introduced a QUIC TLS interface for third-party stacks (`SSL_set_quic_tls_cbs` and six `OSSL_FUNC_SSL_QUIC_TLS_*` callbacks; checked against the headers of the `openssl-3.5` branch). The 3.5 branch is LTS until 2030-04-08. It is used by ngtcp2 (backend marked experimental) and by msquic since 2.6.0. quictls is archived. BoringSSL has no stable API/ABI and no versions.

## Decision

- The first backend is OpenSSL 3.5.x, linked statically into `kuicksilver-native`; a system `libssl.so.3` ≥ 3.5 is optional, Linux only.
- BoringSSL remains the planned fallback backend behind the same interface (not implemented).
- The transport depends on the `QuicCrypto` interface (`QuicTlsSession`, `PacketProtector`), not on the native module. Tests use `NullCryptoProvider` (a provider without encryption, `@DelicateKuicksilverApi`).

## Consequences

- One TLS library on Native for TLS over TCP, QUIC and `KslCrypto`.
- Stable API/ABI within 3.x; system OpenSSL on Linux servers.
- Risks checked in the pre-implementation spike (2026-10-02): the youth of the QUIC interface, APK size, CPU. OpenSSL's lifetime requirements for CRYPTO buffers and transport parameters fall on `ksl`.
- A second backend can be added without changing the transport.

## Rejected

- BoringSSL first: the argument "quiche only works with BoringSSL" no longer applies because the transport is our own; BoringSSL has no versions and no stable ABI.
