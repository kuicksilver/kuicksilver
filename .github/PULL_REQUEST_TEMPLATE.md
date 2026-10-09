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

- [ ] Every commit is signed off (`git commit -s`, Developer Certificate of Origin).
- [ ] AI assistance, if any, is disclosed with an `Assisted-by: <tool>[:<model>]` trailer, and I understand every line.
- [ ] Tests added or changed; a test failed before the fix; security checks have a `negative_*` control.
- [ ] Public API changed: KDoc written, `./gradlew updateKotlinAbi` run and the `api/` dump diff is part of this PR
      (or: no public API change).
- [ ] `checkSpdxHeaders`, `checkLayerDependencies` and the architecture checks pass; new files carry the SPDX header.
- [ ] Docs updated where behaviour changed (guides, `docs/spec/rfc-compliance.md`, `docs/spec/threat-model.md`).
- [ ] `CHANGELOG.md` has an entry under `Unreleased` (or: not user-visible).
