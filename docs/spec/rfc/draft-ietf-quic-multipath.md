<!--
Copyright 2026 The Kuicksilver Authors
SPDX-License-Identifier: Apache-2.0
-->

# RFC 10069 — Managing Multiple Paths for a QUIC Connection (draft-ietf-quic-multipath)

Details of the rows of the [RFC compliance summary](../rfc-compliance.md) for this document. Each section gives the requirement, how Kuicksilver meets it (with the files), the tests that pin it, its history, notes on peers and the open items. Status: ✅ met · 🔶 feature subset or accepted deviation · ⬜ planned · ❌ not planned; "since" is the release from which the current behaviour holds (history below and in [CHANGELOG.md](../../../CHANGELOG.md)).

## <a id="multipath"></a>multipath

Status: ⬜ planned for 0.3.x · [summary](../rfc-compliance.md#quic)

Original row: draft-ietf-quic-multipath (published as RFC 10069 in 2026-11; draft-21 is its last draft).

**Requirement.** Multipath.

**Recorded status.** ⬜ planned for a 0.3.x release, experimental and off by default, with every MUST and SHOULD (owner decision of 2026-11-18; before: later, after 0.3.x, then 0.3.0 from 2026-11-16)

**How it is met.**

- Nothing is owed while the extension is not advertised: draft-21 section 2 "If either of the endpoints does not
  advertise the initial_max_path_id transport parameter, then both endpoints MUST NOT use any frame or mechanism defined
  in this document." We never send `initial_max_path_id`, and a peer's is ignored as an unknown transport parameter.
- `PathId` (`PathId.kt`) is in place for it.

**Open items.**

- Not implemented: draft-ietf-quic-multipath (draft-21) as a whole — the `initial_max_path_id` transport parameter,
  the PATH_ACK, PATH_ABANDON, PATH_STATUS_BACKUP/AVAILABLE, PATH_NEW_CONNECTION_ID, PATH_RETIRE_CONNECTION_ID,
  MAX_PATH_ID, PATHS_BLOCKED and PATH_CIDS_BLOCKED frames, per-path packet number spaces and the per-path nonce. Planned for
  0.3.x: [roadmap](../../roadmap.md#03x--multipath-quic).
