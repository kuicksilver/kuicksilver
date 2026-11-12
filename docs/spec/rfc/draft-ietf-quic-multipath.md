<!--
Copyright 2026 The Kuicksilver Authors
SPDX-License-Identifier: Apache-2.0
-->

# draft-ietf-quic-multipath — Multipath Extension for QUIC (draft-ietf-quic-multipath)

Details of the rows of the [RFC compliance summary](../rfc-compliance.md) for this document. Each section gives the requirement, how Kuicksilver meets it (with the files), the tests that pin it, its history, notes on peers and the open items. Status: ✅ met · 🔶 feature subset · ⬜ planned · ❌ not planned; "since" is the release from which the current behaviour holds (history below and in [CHANGELOG.md](../../../CHANGELOG.md)).

## <a id="multipath"></a>multipath

Status: ⬜ (not scheduled) · [summary](../rfc-compliance.md#quic)

Original row: draft-ietf-quic-multipath.

**Requirement.** Multipath.

**Recorded status.** ⬜ later (after 0.3.x)

**How it is met.**

- Nothing is owed while the extension is not advertised: draft-21 section 2 "If either of the endpoints does not
  advertise the initial_max_path_id transport parameter, then both endpoints MUST NOT use any frame or mechanism defined
  in this document." We never send `initial_max_path_id`, and a peer's is ignored as an unknown transport parameter.
- `PathId` (`PathId.kt`) is in place for it.

**Open items.**

- Not implemented: draft-ietf-quic-multipath (draft-21) as a whole — the `initial_max_path_id` transport parameter,
  the PATH_ACK, PATH_ABANDON, PATH_STATUS_BACKUP/AVAILABLE, PATH_NEW_CONNECTION_ID, PATH_RETIRE_CONNECTION_ID,
  MAX_PATH_ID, PATHS_BLOCKED and PATH_CIDS_BLOCKED frames, per-path packet number spaces and the per-path nonce. Not
  scheduled: listed under "Later" in the [roadmap](../../roadmap.md#later).
