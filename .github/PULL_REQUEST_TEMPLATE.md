<!--
Copyright 2026 The Kuicksilver Authors
SPDX-License-Identifier: Apache-2.0
Security fixes are not proposed here: report them privately (SECURITY.md).
-->

## What and why

<!-- What does this change, and why? Link the issue: "Fixes #123" / "Part of #123". -->

## How it was tested

<!-- Which test failed before the change and passes after it? Which tasks did you run, on which platforms? -->

## Checklist

- [ ] I have the right to submit this change under Apache-2.0 (CONTRIBUTING.md, License of contributions).
- [ ] AI assistance, if any, is disclosed with an `Assisted-by: <tool>[:<model>]` trailer, and I understand every line.
- [ ] Tests (CONTRIBUTING.md, Tests): new functionality has automated tests; a bug fix has a regression test that failed
      before the fix; security checks have a `negative_*` control.
- [ ] Public API changed: KDoc written, `./gradlew updateKotlinAbi` run and the `api/` dump diff is part of this PR
      (or: no public API change).
- [ ] `checkSpdxHeaders`, `checkLayerDependencies` and the architecture checks pass; new files carry the SPDX header.
- [ ] Docs updated where behaviour changed (guides, `docs/spec/rfc-compliance.md` and its details in `docs/spec/rfc/`, `docs/spec/interop.md`, `docs/spec/threat-model.md`).
- [ ] `CHANGELOG.md` has an entry under `Unreleased` (or: not user-visible).
