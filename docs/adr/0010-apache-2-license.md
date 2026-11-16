# ADR-0010. Apache-2.0 license

Date: 2026-10-02. Status: accepted (approved by the owner 2026-10-02).

## Decision

The project is under Apache-2.0 with a `NOTICE` that includes the OpenSSL license (Apache-2.0). Contributions are accepted under Apache-2.0 section 5 (*updated 2026-11-16, owner decision:* the DCO sign-off is no longer required while the project has a single maintainer). No code under the LGPL (kwik) is borrowed; only ideas. Ktor code (Apache-2.0) may be carried over selectively with attribution.

## Consequences

- Compatible with Ktor, OpenSSL, kotlinx; suitable for Maven Central.
- The Apache-2.0 patent clause protects users.
