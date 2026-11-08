# Module kuicksilver-tls

TLS 1.3 (and TLS 1.2 on request) over OpenSSL 3.5: configuration, certificate trust (the platform verifier, a private
CA, SPKI pins, trust on first use), server identities, and TLS over any pair of byte channels. Guide:
`docs/guide/tls.md`.

# Package io.kuicksilver.tls

`tlsConfig { }` and `TlsConfig`, `TrustConfig`, `TlsIdentity`, `TlsConnection.client` / `TlsConnection.server` over
ktor-io channels, certificate verification and `TlsException`, and the QUIC crypto interface (`QuicCrypto`,
`QuicTlsSession`) with its OpenSSL implementation.
