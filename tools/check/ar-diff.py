#!/usr/bin/env python3
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
"""Says where two static archives differ, for tools/check/double-build.sh: "libcrypto.a differs" alone leaves the reader to
unpack both. Members are compared in archive order (name, header fields, bytes); for each one that differs it prints the
member's position and name, the first differing offset and how many bytes differ. The archive index (BSD __.SYMDEF /
__.SYMDEF SORTED / __.SYMDEF_64, System V and GNU "/" and "/SYM64/") is named as such; in a BSD index it also says
whether the differing bytes lie past the last symbol name the index refers to, in the padding of its string table, which
no reader looks at: the trace of an archiver that writes uninitialised memory there (Xcode's ranlib and libtool, why
tools/openssl/build.sh archives the Apple targets with llvm-ar).
Usage: ar-diff.py <a.a> <b.a>   exit 0 identical, 1 different (printed), 2 not two readable archives.
Formats: BSD (#1/<len> names after the header) and System V / GNU (the // name table, /<offset> names)."""
import struct
import sys

MAGIC = b"!<arch>\n"
INDEX_NAMES = ("__.SYMDEF", "__.SYMDEF SORTED", "__.SYMDEF_64", "__.SYMDEF_64 SORTED", "/", "/SYM64/")


class Bad(Exception):
    pass


def members(path):
    """[(name, header fields without name and size, data)] in archive order."""
    try:
        with open(path, "rb") as f:
            d = f.read()
    except OSError as e:
        raise Bad(f"{path}: {e.strerror}")
    if not d.startswith(MAGIC):
        raise Bad(f"{path}: not an ar archive (no !<arch> magic)")
    out, off, names = [], len(MAGIC), b""
    while off < len(d):
        if d[off:off + 1] == b"\n":   # the padding byte after an odd-sized member
            off += 1
            continue
        h = d[off:off + 60]
        if len(h) < 60 or h[58:60] != b"`\n":
            raise Bad(f"{path}: bad member header at offset {off}")
        raw, fields = h[:16].decode("latin-1").rstrip(" "), h[16:48].decode("latin-1").split()
        try:
            size = int(h[48:58])
        except ValueError:
            raise Bad(f"{path}: bad member size at offset {off}")
        body = d[off + 60:off + 60 + size]
        if len(body) < size:
            raise Bad(f"{path}: member at offset {off} runs past the end")
        if raw.startswith("#1/"):   # BSD: the name is the first <len> bytes of the data
            n = int(raw[3:])
            name, body = body[:n].rstrip(b"\0").decode("latin-1"), body[n:]
        elif raw == "//":   # GNU: the long-name table
            names, name = body, "//"
        elif raw.startswith("/") and raw[1:].isdigit():
            s = int(raw[1:])
            e = names.find(b"\n", s)
            name = names[s:e if e >= 0 else len(names)].decode("latin-1").rstrip("/")
        elif raw in ("/", "/SYM64/"):
            name = raw
        else:
            name = raw.rstrip("/")
        out.append((name, fields, body))
        off += 60 + size + (size & 1)
    return out


def bsd_index_unused(name, body):
    """The offsets in a BSD index member past its last referenced symbol name (string-table padding), or None."""
    try:
        if name.startswith("__.SYMDEF_64"):
            w, fmt = 8, "<Q"
        elif name.startswith("__.SYMDEF"):
            w, fmt = 4, "<I"
        else:
            return None
        n = struct.unpack(fmt, body[:w])[0]
        so = w + n
        ss = struct.unpack(fmt, body[so:so + w])[0]
        st = so + w
        if n % (2 * w) or st + ss > len(body):
            return None
        offs = [struct.unpack(fmt, body[w + i * 2 * w:w + i * 2 * w + w])[0] for i in range(n // (2 * w))]
        if not offs:
            return st
        last = max(offs)
        end = body.index(b"\0", st + last) + 1
        return end if end <= st + ss else None
    except (struct.error, ValueError):
        return None


def main(argv):
    if len(argv) != 3:
        print(__doc__.strip().splitlines()[-2], file=sys.stderr)
        return 2
    try:
        a, b = members(argv[1]), members(argv[2])
    except Bad as e:
        print(f"ar-diff: {e}", file=sys.stderr)
        return 2
    lines = []
    if len(a) != len(b):
        lines.append(f"member count: {len(a)} vs {len(b)}")
    for i, ((na, fa, da), (nb, fb, db)) in enumerate(zip(a, b)):
        what = "archive index " if na in INDEX_NAMES else ""
        if na != nb:
            lines.append(f"member {i}: name '{na}' vs '{nb}'")
            continue
        if fa != fb:
            lines.append(f"member {i} {what}'{na}': header fields (mtime uid gid mode) {' '.join(fa)} vs {' '.join(fb)}")
        if da == db:
            continue
        diff = [k for k in range(min(len(da), len(db))) if da[k] != db[k]]
        msg = f"member {i} {what}'{na}': {len(da)} vs {len(db)} bytes"
        if diff:
            msg += f", {len(diff)} differ, offsets {diff[0]}..{diff[-1]}"
            if len(da) == len(db):
                u = bsd_index_unused(na, da)
                if u is not None and u == bsd_index_unused(nb, db) and diff[0] >= u:
                    msg += (" - all past the last symbol name, in the string table's padding"
                            " (an index writer leaving uninitialised bytes there)")
        lines.append(msg)
    for i in range(min(len(a), len(b)), max(len(a), len(b))):
        side, (n, _, d) = ("first", a[i]) if len(a) > len(b) else ("second", b[i])
        lines.append(f"member {i} '{n}' ({len(d)} bytes): only in the {side}")
    if not lines:
        with open(argv[1], "rb") as fa, open(argv[2], "rb") as fb:
            if fa.read() == fb.read():
                return 0
        lines.append("every member is identical: the archive framing differs (padding between members)")
    for line in lines[:20]:
        print(f"     {line}")
    if len(lines) > 20:
        print(f"     ... {len(lines) - 20} more")
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
