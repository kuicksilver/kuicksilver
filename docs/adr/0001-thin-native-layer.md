# ADR-0001. A thin native layer, everything else in Kotlin

Date: 2026-10-02. Status: accepted (approved by the owner 2026-10-02).

## Context

We need QUIC + TLS 1.3 on every KMP platform. Neither the JDK nor Conscrypt offers TLS 1.3 with a QUIC interface; writing our own TLS is the main security risk. Existing QUIC stacks (ngtcp2, quiche, msquic) are written in C/Rust, with different ownership models and dependencies on BoringSSL.

## Decision

Only what cannot be done otherwise is native: OpenSSL, the C shim `ksl`, AEAD and header protection, certificate verification hooks, batched UDP. The QUIC transport (loss recovery, congestion control, streams, datagrams, migration), HTTP/3 with QPACK and the Ktor engines are Kotlin in `commonMain`. ngtcp2 and quiche are not shipped: they are only peers in interop tests and behavioural references.

## Consequences

- One transport codebase on every platform; deterministic tests and a simulator (ADR-0004).
- More work in Kotlin than with a wrapper, but no throwaway C bindings on 7 platforms.
- AEAD and UDP performance stays native.
- The native surface is small and fuzzed with libFuzzer.

## Rejected

- (B) Wrap ngtcp2/nghttp3 first, replace later: throwaway C bindings on 7 platforms, and the risk of staying on the wrapper forever.
- (C) Our own TLS 1.3 in Kotlin: the main security risk; contradicts ADR-0002.
