# ADR-0011. Trust rules: the name can be replaced but not disabled; the pin is always checked

Date: 2026-10-02. Status: accepted (approved by the owner 2026-10-02).

## Context

A typical TLS misconfiguration: "hostname check disabled + system trust" — any publicly valid certificate passes. The real scenarios for replacing the name are TLS proxies and tunnels that present their own certificate rather than the end host's.

## Decision

`TrustConfig`: `Platform` (default) / `AnchoredCa` / `ExpectedName(name, base)` / `Pinned(spki, base)` / `Tofu(store)` / `Custom(verifier)`.
1. The hostname check can be replaced (`ExpectedName`) but not disabled — the API has no mode without a name; `Custom` must check the name by contract.
2. The pin is always checked, even if `base` trusts the chain ("AND", not "OR").
3. The platform verifier is used only for `Platform`; all other modes use the OpenSSL verifier. Every check has a negative control (see threat-model §5).

Cross-check 2026-10-02: the rule "pin always, regardless of the name check" matches OkHttp (`CertificatePinner.check` unconditionally after `HostnameVerifier`) and Android NSC; separating SNI from the verified name matches OpenSSL (`SSL_set_tlsext_host_name` vs `SSL_set1_host`); forbidding the name check from being disabled is stricter than every reference (RFC 9525 §6.6 allows a switch, but "MUST NOT … by default"). The pin is matched against the validated chain (RFC 7469 §2.6), `Custom` is marked `@DelicateKuicksilverApi` after the `danger` module of rustls. Session resumption does not bypass the check: the cache key includes the `TrustConfig` hash and the name.

## Consequences

- One cannot accidentally end up with "trust everything".
- Proxy scenarios are covered without disabling protection.

## Implementation in K1 (2026-10-02)

The rules are implemented in `kuicksilver-tls`: the name is checked by the `ksl` matcher on every path (in pause mode — after the platform verdict), `ExpectedName` substitutes the name from the configuration, pins are compared against the validated chain (`X509_STORE_CTX_get1_chain` on the OpenSSL path, the platform verifier's chain otherwise), resumption re-checks trust against the stored chain. A missing EKU is accepted (RFC 5280 §4.2.1.12, as in Go and webpki), a wrong one is rejected. The negative tests of threat-model §5 items 1–2 are green on JVM, macOS Native and Android.
