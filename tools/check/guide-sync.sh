#!/usr/bin/env bash
# Guide/test drift check: every `// guide:<guide>:<name>` block in docs/guide/*.md must match the block under the same
# marker in a GuideSamplesTest, so the code shown to readers is the code that compiles and runs.
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Usage: guide-sync.sh [repo root]   exit 0: no drift; exit 1: drifts listed on stdout
#
# Matching rules (kept loose on purpose, the tests need scaffolding the guides leave out):
# - A guide block runs from its marker to the next marker or the end of the fenced code block; lines above the first
#   marker of a fenced block are context (values the test defines its own way) and are not compared.
# - A test block runs from its marker to a blank line followed by a line not deeper than the marker, a line indented less than the marker, or another marker at the
#   same or a lower indentation (a marker nested deeper, e.g. inside a `launch {}`, is part of the outer block too).
#   A test marker may carry a note in parentheses, e.g. `// guide:quic:server-accept (the bind)`; several test
#   markers with the same name are read in file order as one block.
# - Lines are compared after dropping comments and blank lines, collapsing whitespace, and replacing addresses and
#   ports (`InetSocketAddress("0.0.0.0", 443)`, `connect("server.test", 443)`, `port = 0`, `127.0.0.1:8080`), and
#   `wait = true` (a test cannot block in `start(wait = true)`).
# - Every guide line must appear in the test block, in order; the test may have extra lines (assertions, timeouts).
set -euo pipefail
root="${1:-$(cd "$(dirname "$0")/../.." && pwd)}"
exec python3 - "$root" <<'PY'
import os, re, sys

root = sys.argv[1]
MARK = re.compile(r'^(\s*)//\s*guide:([a-z0-9-]+):([A-Za-z0-9_-]+)(?:\s*\(([^)]*)\))?\s*$')

def strip_comments(line):
    out, i, in_str = [], 0, None
    while i < len(line):
        c = line[i]
        if in_str:
            out.append(c)
            if c == '\\' and i + 1 < len(line): out.append(line[i + 1]); i += 2; continue
            if c == in_str: in_str = None
        elif c in '"\'':
            in_str = c; out.append(c)
        elif line.startswith('//', i):
            break
        elif line.startswith('/*', i):
            end = line.find('*/', i + 2)
            if end < 0: break
            i = end + 2; continue
        else:
            out.append(c)
        i += 1
    return ''.join(out)

ADDR = r'"(?:\d{1,3}(?:\.\d{1,3}){3}|[A-Za-z0-9.-]+\.(?:test|example|com|org|local)|localhost|::1?)"'
def normalize(line):
    s = strip_comments(line).strip()
    if not s: return None
    s = re.sub(r'\b(\d{1,3}(?:\.\d{1,3}){3}|localhost):\d+', r'<addr>:<port>', s)
    s = re.sub(r'(InetSocketAddress|connect)\(\s*' + ADDR + r'\s*,\s*[A-Za-z0-9_.]+\s*\)', r'\1(<addr>, <port>)', s)
    s = re.sub(r'\bport\s*=\s*[0-9]+\b', 'port = <port>', s)
    s = re.sub(r'\bwait\s*=\s*(true|false)\b', 'wait = <wait>', s)
    s = re.sub(r'\s+', ' ', s)
    s = re.sub(r'\s*([(){}\[\],;])\s*', r'\1', s)
    return s

# guide blocks: key -> list of (normalized, original) lines
guides, guide_where = {}, {}
gdir = os.path.join(root, 'docs', 'guide')
for name in sorted(os.listdir(gdir)):
    if not name.endswith('.md'): continue
    path = os.path.join(gdir, name)
    in_code, key = False, None
    for no, line in enumerate(open(path, encoding='utf-8'), 1):
        line = line.rstrip('\n')
        if line.lstrip().startswith('```'):
            in_code = not in_code; key = None; continue
        if not in_code: continue
        m = MARK.match(line)
        if m:
            key = f'{m.group(2)}:{m.group(3)}' + (f' ({m.group(4)})' if m.group(4) else '')
            if key in guides: print(f'DUPLICATE guide marker {key} at docs/guide/{name}:{no}')
            guides[key] = []; guide_where[key] = f'docs/guide/{name}:{no}'
            continue
        if key is not None:
            n = normalize(line)
            if n: guides[key].append((n, line.strip()))

# test blocks: key -> list of runs; a run is a list of (normalized, original)
tests, test_where = {}, {}
for top, dirs, files in os.walk(root):
    dirs[:] = [d for d in dirs if d not in ('build', '.git', '.gradle', '.worktrees', '.claude', 'node_modules', 'plans')]
    if '/src/' not in top + '/' or 'Test' not in top: continue
    for f in files:
        if not f.endswith('.kt'): continue
        path = os.path.join(top, f)
        lines = open(path, encoding='utf-8').read().split('\n')
        i = 0
        while i < len(lines):
            m = MARK.match(lines[i])
            if not m: i += 1; continue
            indent = len(m.group(1))
            name = f'{m.group(2)}:{m.group(3)}'
            qualified = name + (f' ({m.group(4)})' if m.group(4) else '')
            key = qualified if qualified in guides else name
            run, j = [], i + 1
            while j < len(lines):
                l = lines[j]
                if not l.strip():   # the formatter puts blank lines between when branches: a blank line ends the block only before a shallower line
                    k = j + 1
                    while k < len(lines) and not lines[k].strip(): k += 1
                    if k >= len(lines) or len(lines[k]) - len(lines[k].lstrip()) <= indent: break
                    j = k; continue
                if len(l) - len(l.lstrip()) < indent: break
                if MARK.match(l) and len(l) - len(l.lstrip()) <= indent: break
                n = normalize(l)
                if n: run.append((n, l.strip()))
                j += 1
            tests.setdefault(key, []).append(run)
            test_where.setdefault(key, f'{os.path.relpath(path, root)}:{i + 1}')
            i += 1

drifts = 0
for key, glines in guides.items():
    if key not in tests:
        print(f'DRIFT {key} ({guide_where[key]}): no test carries this marker'); drifts += 1; continue
    # the formatter may wrap one guide line over several test lines (and the guide may show a wrapped call on one line):
    # compare the joined text, each guide line as a substring found in order, with trailing commas before a closing bracket dropped
    def joined(parts):
        t = re.sub(r'\s+', ' ', ' '.join(parts).replace(';', ' '))   # `a; b` in a guide is `a` and `b` on two test lines
        t = re.sub(r'\s*([(){}\[\],])\s*', r'\1', t)
        t = re.sub(r',(?=[)\]}])', '', t).rstrip(',')   # trailing commas: the formatter adds them before a closing bracket
        return t.replace('{', '').replace('}', '').replace(' ', '')   # braces and spaces: the formatter wraps branches and chains
    text = joined(n for run in tests[key] for n, _ in run)
    gi, pos = 0, 0
    while gi < len(glines):
        at = text.find(joined([glines[gi][0]]), pos)
        if at < 0: break
        pos = at + len(joined([glines[gi][0]])); gi += 1
    if gi < len(glines):
        drifts += 1
        print(f'DRIFT {key} ({guide_where[key]} vs {test_where[key]}): guide line not found in the test, in order:')
        print(f'    guide: {glines[gi][1]}')
        cands = [o for run in tests[key] for _, o in run]
        near = [o for o in cands if o.split('(')[0] == glines[gi][1].split('(')[0]]
        if near: print(f'    test:  {near[0]}')
for key in tests:
    if key not in guides:
        print(f'DRIFT {key} ({test_where[key]}): test marker without a guide block'); drifts += 1
print(f'guide-sync: {len(guides)} guide blocks, {drifts} drift(s)')
sys.exit(1 if drifts else 0)
PY
