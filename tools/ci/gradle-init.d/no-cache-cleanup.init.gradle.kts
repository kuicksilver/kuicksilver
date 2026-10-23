// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
// Mounted as init.d of the container-private Gradle user home by tools/ci/docker-jvm.sh: that home lives as long as the
// container, so a cleanup could only cost time; and if a future change ever pointed it at a shared cache again, a cleanup
// from inside a container (whose access journal sees /root/... paths, never the host's) would delete what the host still uses.
beforeSettings {
    caches {
        cleanup = Cleanup.DISABLED
    }
}
