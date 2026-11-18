<!--
Copyright 2026 The Kuicksilver Authors
SPDX-License-Identifier: Apache-2.0
-->

# Governance

How Kuicksilver is run: who holds which role, how decisions are made and recorded, how a maintainer is added, and what
happens to the project's accounts and keys if a maintainer becomes unavailable. Where something is not in place yet,
this page says so.

## Model

Kuicksilver is a maintainer-led project with, today, **one maintainer**. The maintainer decides what is merged and
released, and records decisions that shape the project in the repository (below), so that anyone can see why the code
is the way it is and continue from there. Everyone else takes part as a contributor: issues, pull requests, reviews and
security reports are welcome from anyone, under [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md) and the
[Code of Conduct](CODE_OF_CONDUCT.md).

## Roles

| Role | Who | Responsibilities | Rights |
|---|---|---|---|
| Maintainer | one person, the GitHub account `kinchpik` (the owner listed in [`.github/CODEOWNERS`](.github/CODEOWNERS)) | reviews and merges every change ([docs/process.md](docs/process.md), stages 2 and 5); runs the release gate and makes releases ([docs/release.md](docs/release.md)); holds the release signing key; handles vulnerability reports and OpenSSL advisories within the targets of [SECURITY.md](SECURITY.md); moderates under the [Code of Conduct](CODE_OF_CONDUCT.md) (`conduct@kuicksilver.io`); decides the scope of each release ([docs/roadmap.md](docs/roadmap.md)) and accepts architecture decisions ([docs/adr/](docs/adr/README.md)) | owner of the `kuicksilver` GitHub organization; write and admin rights on its repositories; the `io.kuicksilver` namespace on Maven Central; the `kuicksilver.io` domain and its mail addresses |
| Reviewer | nobody yet | reviews pull requests against the [Review checklist](CONTRIBUTING.md#review-checklist) and the RFC text; triages issues | triage rights on the repository; no merge rights |
| Contributor | anyone | follows [CONTRIBUTING.md](CONTRIBUTING.md): an issue first for anything beyond a small fix, tests with every change ([Tests](CONTRIBUTING.md#tests)), the [License of contributions](CONTRIBUTING.md#license-of-contributions) | opens issues, discussions and pull requests; reports vulnerabilities privately |

## How decisions are made

- **Everyday changes** (a bug fix, a test, documentation): the maintainer reviews the change against the
  [Review checklist](CONTRIBUTING.md#review-checklist) and the RFC text, and merges it once the checks of
  [docs/process.md](docs/process.md) pass. A deviation from a MUST or SHOULD of an RFC is not accepted as "partial":
  it is fixed, or the [compliance matrix](docs/spec/rfc-compliance.md) says the requirement is not met.
- **Changes of behaviour, public API, dependencies or platforms**: an issue first, where the use case is discussed
  before the API ([Proposing a change](CONTRIBUTING.md#proposing-a-change)). New public API starts experimental; the
  stability rules are in [docs/stability.md](docs/stability.md).
- **Decisions that shape the architecture or the scope** (a new module, a backend, a protocol the project will or will
  not implement) are written down as an **Architecture Decision Record** in [docs/adr/](docs/adr/README.md): the
  context, the decision, its consequences and the alternatives rejected, with the status proposed, accepted or
  superseded. A decision is changed by a new ADR that supersedes the old one (for example ADR-0015 superseded ADR-0008),
  never by editing history. What each release contains, and what the project will not do, is in
  [docs/roadmap.md](docs/roadmap.md).
- **Security-relevant changes** update the [threat model](docs/spec/threat-model.md) in the same commit, and every
  security check has a `negative_*` test that fails without it.
- **Disagreement** is discussed in the issue or pull request, on technical grounds: the RFC text, measurements, tests,
  and what reference implementations do ([docs/process.md](docs/process.md), stage 3). With one maintainer, the
  maintainer decides and states the reason in the issue, the pull request or the ADR.

## Adding a maintainer or a reviewer

The project wants a second maintainer. A contributor can become a **reviewer** after a record of reviewed and merged
contributions, and a **maintainer** after a sustained record as a reviewer, including work on releases or security
fixes. The steps:

1. The maintainer proposes the person in a public issue (the person agrees first); the issue stays open for at least
   two weeks for comments.
2. The new reviewer gets triage rights; a new maintainer gets write rights, then organization owner rights, access to
   the private security advisories and the `conduct@` address, and is added to `.github/CODEOWNERS` and to the Roles
   table above in the same pull request.
3. A new maintainer reads [docs/release.md](docs/release.md) and runs a release-candidate dry run of the gate before
   making a release.

Once there are two or more maintainers, these rules apply instead of a single decision maker:

- a change is merged after a review by a maintainer who did not write it;
- an ADR is accepted, and a maintainer added or removed, by consensus of the maintainers; when there is no consensus
  after discussion, by a simple majority of them;
- a release is made by one maintainer after another has checked its gate record and changelog.

A maintainer can step down at any time by saying so in an issue; their rights are removed and the accounts and keys
they held are handed over as in the access continuity plan below. A maintainer who has not responded for six months
can be moved to emeritus status by the other maintainers.

## Access continuity

What the project depends on, and who holds it today:

| Asset | Held by | What keeps it recoverable today |
|---|---|---|
| The `kuicksilver` GitHub organization and its repositories | the maintainer, the only organization owner | the source, the issues and the release assets are public; every repository can be forked |
| The release signing key (`22C1F2E4FCE94B28EB2C7DB0492ABD95C8D0EC68`) | the maintainer, offline in a local key ring | the public key is in the repository ([`tools/release/kuicksilver-release-key.asc`](tools/release/kuicksilver-release-key.asc)) and on key servers, so signatures of past releases stay verifiable ([docs/verifying.md](docs/verifying.md)) |
| The `io.kuicksilver` namespace on Maven Central | the maintainer's Central Portal account | published versions stay on Central for good; the namespace is tied to the domain by a DNS TXT record ([docs/release.md](docs/release.md)) |
| The `kuicksilver.io` domain, its DNS and mail addresses | the maintainer | — |

Everything needed to build, check, release and verify the project without its current maintainer is in the
repository: the build and its prerequisites ([CONTRIBUTING.md, Building](CONTRIBUTING.md#building)), the gate and the
checks ([docs/process.md](docs/process.md)), the release procedure and the accounts it needs
([docs/release.md](docs/release.md)), and the verification of published artifacts ([docs/verifying.md](docs/verifying.md)).
The code is under Apache-2.0, so the project can always be continued in a fork.

**Open item.** One person holds every asset in the table above. If that person became unavailable, nobody else could
administer the organization, merge into its repositories, publish a release under `io.kuicksilver`, sign it with the
release key, or renew the domain. The plan is:

1. a second trusted person with owner rights on the `kuicksilver` GitHub organization;
2. the release signing key's private part, a revocation certificate, and the Central Portal and domain credentials in
   escrow that this person can open if the maintainer is unavailable;
3. this section updated to say who holds what, by role, once both are in place.

Until then, access to the project's organization, key, namespace and domain depends on one person.
