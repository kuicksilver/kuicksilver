/* Copyright 2026 The Kuicksilver Authors
 * SPDX-License-Identifier: Apache-2.0 */
/* Files the C tests write: owner-only, created through no symbolic link. Needs _POSIX_C_SOURCE 200809L, and _DARWIN_C_SOURCE on macOS, for O_NOFOLLOW. */
#ifndef KSL_TEST_FILES_H
#define KSL_TEST_FILES_H
#include <stdio.h>
#include <fcntl.h>
#include <sys/stat.h>
#ifdef _WIN32
#include <io.h>
#else
#include <unistd.h>
#endif

/* fopen(path, "w") with mode 0600 instead of 0666 & ~umask, refusing a symbolic link at path. An existing file is
   truncated, as fopen does (the tests rewrite their files), and set to 0600 as well. Windows: _S_IREAD | _S_IWRITE (no
   mode bits for others there); the file gets the directory's ACL. */
static inline FILE *fopen_private(const char *path) {
#ifdef _WIN32
    int fd = _open(path, _O_WRONLY | _O_CREAT | _O_TRUNC | _O_TEXT, _S_IREAD | _S_IWRITE);
    FILE *f = fd < 0 ? NULL : _fdopen(fd, "w");
    if (fd >= 0 && !f)
        _close(fd);
#else
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd >= 0 && fchmod(fd, 0600) != 0) {
        close(fd);
        return NULL;
    }
    FILE *f = fd < 0 ? NULL : fdopen(fd, "w");
    if (fd >= 0 && !f)
        close(fd);
#endif
    return f;
}
#endif
