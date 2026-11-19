# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
"""The "How we verify" section of the documentation site: tables and badges generated from the CI results of the published
commit, in every language of tools/docs/i18n.py (English canonical; the data is computed once and only the labels differ).

Two steps, so that the CI jobs upload a few kilobytes of counts instead of their reports:

  verify.py collect --lane NAME --host LABEL --out FILE [--sha SHA --run-id ID] [sources...]
      run at the end of a build.yml job (from the repository root): reads what the job produced and writes one JSON record
      with the commit, run and attempt it belongs to (GITHUB_SHA, GITHUB_RUN_ID, GITHUB_RUN_ATTEMPT by default). Only
      counts, outcomes, test and file names and sizes are kept: no path, host name or output of the runner. A source that
      matches nothing, or a declared h2spec run without a report, makes the exit status 1 after the record is written
      (--allow-empty: a source may match nothing). Sources (each may repeat):
        --junit TARGET:GLOB         JUnit XML reports (Gradle test-results, Android connected tests); the module is the
                                    first path component of each file
        --cases MODULE              also keep each test case of MODULE (the engine interop pairs)
        --gtest TARGET:GLOB         Kotlin/Native test executable logs (GTest format), one log per module named <module>.log
        --compiled TARGET:OUTCOME   a target that is compiled but not run (OUTCOME: the step's outcome, success or other)
        --size KIND:GLOB            artifact sizes; KIND aar (with the libksl .so of each ABI inside), jni (the platform
                                    from the libksl_<abi>_<platform> name), klib (a file or an unpacked directory under
                                    build/classes/kotlin/<target>/), jar, zip, xcframework (the framework binary of
                                    each slice of an .xcframework directory)
        --skip-module MODULE        no size of MODULE (a module that is not published)
        --h2spec-manifest FILE      the runs tools/interop/h2spec.sh declared (build/h2spec/variants.txt: kind, variant,
                                    report directory) and their reports
        --interop-runner IMAGE:GLOB QUIC Interop Runner result files (tools/interop/run-local.sh)
  verify.py build --sha SHA --version V --ref REF --src REPO --out VERSION_DIR [--meta FILE --data DIR]
                  [--fuzz-meta FILE --fuzz-stats DIR] [--fuzz-targets FILE] [--perf-meta FILE --perf DIR] [--base-url URL]
      writes VERSION_DIR/verify/*.html (English), VERSION_DIR/<lang>/verify/*.html, VERSION_DIR/verify/badges/*.svg and
      VERSION_DIR/verify/data.json. --meta is the build.yml run (gh run view --json: databaseId, attempt, headSha,
      createdAt, url, event, conclusion) and --data the downloaded verify-* artifacts. The run must be a successful run of
      exactly SHA and every record must name SHA, that run and one of its attempts (the newest attempt of each lane
      counts; two records of one lane and attempt are refused), else nothing is written and the exit status is 1 (no
      stale or foreign data is ever shown as this commit's). A missing run, or a run whose records are gone (artifacts
      expire), is "no data" on the page, never a failure; data.json then has no lanes. The fuzzing
      campaign (fuzz.yml, weekly) and perf.yml run on other commits: they are shown with their own commit and date, never
      as this commit's. REPO is the published commit's checkout (RFC table, committed corpora and benchmarks).
  verify.py keep --new VERSION_DIR --old VERSION_DIR [--base-url URL]
      the Pages workflow, before it replaces a published version: when the new pages have no CI data (data.json without
      lanes), the published data of the same commit is kept, rendered again in every language together; if its schema
      is not this one or it does not render, the published verify directories are kept as they are; with no published
      pages, the new "no data" pages stay (a warning). It decides the verify section only and never stops the site.
  verify.py check-pairs --sources DIR
      every test class of the engine interop sources (DIR) has a row in tools/docs/engine-pairs.tsv (exit 1 otherwise)

Tests: tools/docs/verify-test.sh (fixtures in tools/docs/testdata/verify/).
"""
import argparse
import glob
import html
import importlib.util
import json
import os
import re
import statistics
import sys
import xml.etree.ElementTree as ET
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_URL = "https://github.com/kuicksilver/kuicksilver"
SITE_URL = "https://kuicksilver.github.io/kuicksilver/"
SCHEMA = 2   # 2: run_attempt
# the version of verify/data.json (the model the pages are rendered from): raise it with any change of its keys, so that
# keep never renders an older one with code that reads it differently
MODEL_SCHEMA = 2   # 2: dir and snapshot (the development snapshot /dev/)
SHA = re.compile(r"^[0-9a-f]{40}$")
# the platform matrix, in this order; a target without a record shows "no data"
TARGETS = ["jvm", "android", "iosArm64", "iosSimulatorArm64", "macosArm64", "linuxX64", "linuxArm64", "mingwX64"]
PAGES = ["index", "platforms", "interop", "conformance", "fuzzing", "sizes", "benchmarks", "rfc", "how"]
STATUS = ["✅", "🔶", "⬜", "❌"]


def _load(name, file):
    sys.dont_write_bytecode = True   # no __pycache__ next to the tools
    spec = importlib.util.spec_from_file_location(name, os.path.join(HERE, file))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


i18n = _load("ksl_i18n", "i18n.py")
site = _load("ksl_site", "site.py")

STYLE = site.STYLE + """
header nav.lang { margin-left: auto; display: flex; gap: 12px; }
header nav.lang a[aria-current] { font-weight: 600; color: var(--fg); text-decoration: none; }
.prov { color: var(--muted); font-size: 90%; }
.note { border-left: 4px solid var(--line); padding: 4px 12px; color: var(--muted); }
.nodata { color: var(--muted); font-style: italic; }
.pass { color: #1a7f37; font-weight: 600; } .fail { color: #cf222e; font-weight: 600; } .warn { color: #9a6700; font-weight: 600; }
@media (prefers-color-scheme: dark) { .pass { color: #3fb950; } .fail { color: #f85149; } .warn { color: #d29922; } }
td.num, th.num { text-align: right; font-variant-numeric: tabular-nums; }
.badges img { margin-right: 6px; }
"""


class Refused(Exception):
    """Data that does not belong to the published commit and run: the build writes nothing."""


# ---------------------------------------------------------------------------------------------------------------- collect

def _split(spec, what):
    key, sep, value = spec.partition(":")
    if not sep or not key or not value:
        sys.exit(f"verify.py: {what} '{spec}' is not KEY:VALUE")
    return key, value


def _files(pattern):
    return sorted(p for p in glob.glob(pattern, recursive=True) if os.path.isfile(p))


def _module(path):
    parts = os.path.normpath(path).split(os.sep)
    return parts[0] if len(parts) > 1 else ""


def parse_junit(path):
    """(cases, ok): every <testcase> of a JUnit XML file as (classname, name, outcome pass|fail|skip)."""
    try:
        root = ET.parse(path).getroot()
    except ET.ParseError:
        return [], False
    cases = []
    for tc in root.iter("testcase"):
        tags = {c.tag for c in tc}
        outcome = "fail" if tags & {"failure", "error"} else "skip" if "skipped" in tags else "pass"
        cases.append((tc.get("classname", ""), tc.get("name", ""), outcome))
    return cases, True


GTEST_TOTAL = re.compile(r"^\[=+\] (\d+) tests? from \d+ test (?:cases|suites) ran")
GTEST_PASSED = re.compile(r"^\[ *PASSED *\] (\d+) tests?")
GTEST_FAILED = re.compile(r"^\[ *FAILED *\] (\d+) tests?, listed below")
GTEST_SKIPPED = re.compile(r"^\[ *(?:SKIPPED|IGNORED) *\] (\d+) tests?")


def parse_gtest(path):
    raw = open(path, "rb").read()
    text = raw.decode("utf-16") if raw[:2] in (b"\xff\xfe", b"\xfe\xff") else raw.decode("utf-8-sig", errors="replace")
    total = passed = failed = skipped = None
    for line in text.splitlines():
        line = re.sub(r"^\S*Z ", "", line.strip())   # a timestamp prefix, as in a downloaded Actions log
        for rx, name in ((GTEST_TOTAL, "total"), (GTEST_PASSED, "passed"), (GTEST_FAILED, "failed"), (GTEST_SKIPPED, "skipped")):
            m = rx.match(line)
            if m:
                if name == "total":
                    total = int(m.group(1))
                elif name == "passed":
                    passed = int(m.group(1))
                elif name == "failed":
                    failed = int(m.group(1))
                else:
                    skipped = int(m.group(1))
    if total is None:
        # no summary: the executable crashed or was killed before the end
        return {"tests": 0, "passed": 0, "failed": 0, "skipped": 0, "status": "error"}
    failed = failed or 0
    skipped = skipped if skipped is not None else max(0, total - failed - (passed or 0))
    passed = passed if passed is not None else total - failed - skipped
    return {"tests": total, "passed": passed, "failed": failed, "skipped": skipped,
            "status": "fail" if failed else "pass" if total else "empty"}


def _row(target, host, module, counts):
    return dict(target=target, host=host, module=module, **counts)


def _tree_size(path):
    if os.path.isfile(path):
        return os.path.getsize(path)
    return sum(os.path.getsize(os.path.join(d, f)) for d, _, fs in os.walk(path) for f in fs)


def collect(args):
    sha = args.sha or os.environ.get("GITHUB_SHA", "")
    run_id = args.run_id or os.environ.get("GITHUB_RUN_ID", "")
    attempt = args.run_attempt or os.environ.get("GITHUB_RUN_ATTEMPT", "") or "1"
    if not SHA.match(sha):
        sys.exit(f"verify.py collect: '{sha}' is not a commit SHA (--sha or GITHUB_SHA)")
    if not str(run_id).isdigit():
        sys.exit(f"verify.py collect: '{run_id}' is not a run id (--run-id or GITHUB_RUN_ID)")
    if not str(attempt).isdigit():
        sys.exit(f"verify.py collect: '{attempt}' is not a run attempt (--run-attempt or GITHUB_RUN_ATTEMPT)")
    # what the job was asked for and did not produce: the record is still written (it shows what there is), and the
    # exit status is 1 so the job says so (--allow-empty for a source that may legitimately match nothing)
    problems = []

    def matched(what, spec, files):
        if not files and not args.allow_empty:
            problems.append(f"{what} {spec} matched nothing")
        return files

    rec = {"schema": SCHEMA, "sha": sha, "run_id": int(run_id), "run_attempt": int(attempt), "lane": args.lane, "host": args.host, "results": [],
           "cases": [], "compiled": [], "sizes": [], "conformance": [], "interop_runner": [], "fuzz_regression": None}
    fuzz = {"tests": 0, "failed": 0}
    case_modules = set(args.cases or [])
    for spec in args.junit or []:
        target, pattern = _split(spec, "--junit")
        per_module = {}
        for f in matched("--junit", spec, _files(pattern)):
            mod = _module(f)
            cases, ok = parse_junit(f)
            c = per_module.setdefault(mod, {"tests": 0, "passed": 0, "failed": 0, "skipped": 0, "broken": 0})
            if not ok:
                c["broken"] += 1
            for cls, name, outcome in cases:
                c["tests"] += 1
                c[{"pass": "passed", "fail": "failed", "skip": "skipped"}[outcome]] += 1
                if ".fuzz." in cls and target == "jvm":
                    fuzz["tests"] += 1
                    fuzz["failed"] += outcome == "fail"
                if mod in case_modules:
                    rec["cases"].append({"module": mod, "class": cls.rsplit(".", 1)[-1], "name": name, "outcome": outcome})
        for mod, c in sorted(per_module.items()):
            broken = c.pop("broken")
            c["status"] = "error" if broken else "fail" if c["failed"] else "pass" if c["tests"] else "empty"
            rec["results"].append(_row(target, args.host, mod, c))
    if fuzz["tests"]:
        rec["fuzz_regression"] = fuzz
    for spec in args.gtest or []:
        target, pattern = _split(spec, "--gtest")
        for f in matched("--gtest", spec, _files(pattern)):
            rec["results"].append(_row(target, args.host, os.path.basename(f).rsplit(".", 1)[0], parse_gtest(f)))
    for spec in args.compiled or []:
        target, outcome = _split(spec, "--compiled")
        rec["compiled"].append({"target": target, "host": args.host, "outcome": outcome})
    for spec in args.size or []:
        kind, pattern = _split(spec, "--size")
        for f in matched("--size", spec, sorted(glob.glob(pattern, recursive=True))):
            if _module(f) in (args.skip_module or []):
                continue
            name = os.path.basename(f.rstrip("/"))
            if kind == "klib":
                parts = os.path.normpath(f).split(os.sep)
                target = parts[parts.index("kotlin") + 1] if "kotlin" in parts[:-1] else ""
                rec["sizes"].append({"kind": "klib", "name": _module(f), "target": target, "bytes": _tree_size(f)})
            elif kind == "jni":
                # libksl_<abi>_<platform>.<ext> names its platform; another file is named by its directory
                m = re.match(r"^libksl_\d+_(.+)\.(?:so|dylib|dll)$", name)
                rec["sizes"].append({"kind": "jni", "name": name, "target": m.group(1) if m else os.path.basename(os.path.dirname(f)),
                                     "bytes": os.path.getsize(f)})
            elif kind == "xcframework":
                # each slice's framework binary (<slice>/<Name>.framework/<Name>): what an app embeds
                for b in matched("--size", f"{spec} (framework binaries)", sorted(glob.glob(os.path.join(f, "*", "*.framework", "*")))):
                    fw = os.path.basename(os.path.dirname(b))
                    if os.path.isfile(b) and os.path.basename(b) == fw[: -len(".framework")]:
                        rec["sizes"].append({"kind": "framework", "name": fw, "target": os.path.basename(os.path.dirname(os.path.dirname(b))),
                                             "bytes": os.path.getsize(b)})
            elif kind in ("aar", "jar", "zip"):
                rec["sizes"].append({"kind": kind, "name": name, "target": "", "bytes": os.path.getsize(f)})
                if kind == "aar":
                    with zipfile.ZipFile(f) as z:
                        for i in z.infolist():
                            m = re.match(r"^jni/([^/]+)/(libksl[^/]*\.so)$", i.filename)
                            if m:
                                rec["sizes"].append({"kind": "aar-so", "name": m.group(2), "target": m.group(1),
                                                     "bytes": i.file_size})
            else:
                sys.exit(f"verify.py collect: unknown size kind '{kind}'")
    # h2spec: the runs tools/interop/h2spec.sh declared in its manifest ("<kind> <variant> <report dir>" per line, written
    # before any run); a declared run without a report is shown as incomplete and fails the collect
    for path in args.h2spec_manifest or []:
        if not os.path.isfile(path):
            problems.append(f"--h2spec-manifest {path}: no manifest (h2spec.sh did not start)")
            continue
        for line in open(path, encoding="utf-8"):
            cols = line.split()
            if len(cols) != 3:
                continue
            kind, variant, d = cols
            entry = {"suite": "h2spec", "variant": variant, "host": f"{args.host} ({kind} server)", "tests": 0, "passed": 0, "skipped": 0, "failed": 0,
                     "status": "error"}
            report = os.path.join(d, "h2spec.txt")   # the report directory, relative to the repository root as h2spec.sh writes it
            m = None
            if os.path.isfile(report):
                for rl in open(report, encoding="utf-8", errors="replace"):
                    m = re.match(r"^(\d+) tests, (\d+) passed, (\d+) skipped, (\d+) failed", rl.strip()) or m
            if m:
                t, p, sk, fl = (int(x) for x in m.groups())
                entry.update(tests=t, passed=p, skipped=sk, failed=fl, status="fail" if fl or sk or p != t else "pass")
            else:
                problems.append(f"h2spec {kind} {variant}: declared in {path}, no summary in {d}/h2spec.txt")
            rec["conformance"].append(entry)
    for spec in args.interop_runner or []:
        image, pattern = _split(spec, "--interop-runner")
        for f in matched("--interop-runner", spec, _files(pattern)):
            try:
                r = json.load(open(f, encoding="utf-8"))
            except (OSError, ValueError):
                continue
            servers, clients = r.get("servers") or [], r.get("clients") or []
            for ci, client in enumerate(clients):
                for si, server in enumerate(servers):
                    idx = ci * len(servers) + si
                    cells = (r.get("results") or [])[idx] if idx < len(r.get("results") or []) else []
                    for cell in cells or []:
                        rec["interop_runner"].append({"image": image, "server": server, "client": client,
                                                      "case": cell.get("name", ""), "result": cell.get("result", "")})
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(rec, f, indent=1, sort_keys=True)
    n = len(rec["results"])
    print(f"verify.py collect: {args.out}: {n} test records, {len(rec['cases'])} cases, {len(rec['sizes'])} sizes, "
          f"{len(rec['interop_runner'])} interop cells", file=sys.stderr)
    for p in problems:
        print(f"verify.py collect: {p}", file=sys.stderr)
    return 1 if problems else 0


# ------------------------------------------------------------------------------------------------------------- the model

def load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def load_ci(meta_path, data_dir, sha):
    """(meta, records) of the build.yml run of SHA; (None, []) when there is no run. Raises Refused on anything that is not
    exactly that commit's successful run."""
    if not meta_path or not os.path.isfile(meta_path):
        return None, []
    meta = load_json(meta_path)
    if meta.get("headSha") != sha:
        raise Refused(f"the build.yml run {meta.get('databaseId')} is of commit {meta.get('headSha')}, not {sha}")
    if meta.get("conclusion") != "success":
        raise Refused(f"the build.yml run {meta.get('databaseId')} concluded '{meta.get('conclusion')}', not success")
    if meta.get("event") == "pull_request":
        raise Refused(f"the build.yml run {meta.get('databaseId')} is a pull_request run (it built a merge commit)")
    by_lane, seen = {}, set()
    for f in sorted(glob.glob(os.path.join(data_dir or "", "**", "*.json"), recursive=True)) if data_dir else []:
        rec = load_json(f)
        if rec.get("schema") != SCHEMA:
            raise Refused(f"{os.path.basename(f)}: schema {rec.get('schema')}, expected {SCHEMA}")
        if rec.get("sha") != sha:
            raise Refused(f"{os.path.basename(f)} (lane {rec.get('lane')}) is of commit {rec.get('sha')}, not {sha}")
        if rec.get("run_id") != meta.get("databaseId"):
            raise Refused(f"{os.path.basename(f)} (lane {rec.get('lane')}) is from run {rec.get('run_id')}, not {meta.get('databaseId')}")
        attempt = rec.get("run_attempt")
        if not isinstance(attempt, int) or attempt < 1 or attempt > int(meta.get("attempt") or 1):
            raise Refused(f"{os.path.basename(f)} (lane {rec.get('lane')}) is from attempt {attempt}, the run has {meta.get('attempt') or 1}")
        # a re-run job uploads its lane again under a new attempt: only the newest attempt of a lane counts (an earlier,
        # failed attempt's record never shows on the successful run); two records of one lane and attempt are refused
        if (rec["lane"], attempt) in seen:
            raise Refused(f"two records of lane {rec['lane']} from attempt {attempt}")
        seen.add((rec["lane"], attempt))
        prev = by_lane.get(rec["lane"])
        if not prev or prev["run_attempt"] < attempt:
            by_lane[rec["lane"]] = rec
    return meta, [by_lane[k] for k in sorted(by_lane)]


def load_pairs(path):
    """engine-pairs.tsv: class, test-name regex ('*' for all), client, server, wire; the first matching row wins."""
    rows = []
    for line in open(path, encoding="utf-8"):
        line = line.rstrip("\n")
        if not line.strip() or line.startswith("#"):
            continue
        cols = line.split("\t")
        if len(cols) != 5:
            sys.exit(f"verify.py: {path}: not 5 tab-separated columns: {line!r}")
        rows.append(cols)
    return rows


def pair_of(rows, cls, name):
    for c, rx, client, server, wire in rows:
        if c == cls and (rx == "*" or re.search(rx, name)):
            return client, server, wire
    return None


def check_pairs(sources, pairs_path):
    rows = load_pairs(pairs_path)
    known = {r[0] for r in rows}
    classes = set()
    for d, _, files in os.walk(sources):
        for f in files:
            if f.endswith(".kt"):
                for m in re.finditer(r"^(?:internal |public )?class (\w+Test)\b", open(os.path.join(d, f), encoding="utf-8").read(), re.M):
                    classes.add(m.group(1))
    missing = sorted(classes - known)
    stale = sorted(known - classes)
    for c in missing:
        print(f"check-pairs: {c} has no row in {pairs_path}")
    for c in stale:
        print(f"check-pairs: {pairs_path} names {c}, which is not a test class of {sources}")
    print(f"check-pairs: {len(classes)} test classes, {len(rows)} rows", file=sys.stderr)
    return 1 if missing or stale or not classes else 0


def rfc_summary(path):
    sections, rows, section = [], [], None
    if not os.path.isfile(path):
        return None
    for line in open(path, encoding="utf-8"):
        if line.startswith("## "):
            section = line[3:].strip()
            continue
        if section and line.startswith("| ") and not line.startswith("| RFC |"):
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            if len(cells) >= 6 and cells[2] in STATUS:
                m = re.search(r"\]\(([^)]+)\)", cells[5])
                rows.append({"section": section, "rfc": cells[0], "topic": cells[1], "status": cells[2], "since": cells[3],
                             "summary": cells[4], "details": m.group(1) if m else ""})
                if section not in sections:
                    sections.append(section)
    per = {s: {k: sum(1 for r in rows if r["section"] == s and r["status"] == k) for k in STATUS} for s in sections}
    total = {k: sum(1 for r in rows if r["status"] == k) for k in STATUS}
    return {"sections": per, "total": total, "open": [r for r in rows if r["status"] in ("🔶", "❌")]}


def median(xs):
    return statistics.median(xs) if xs else None


def benchmarks_summary(src):
    d = os.path.join(src, "docs", "benchmarks")
    if not os.path.isdir(d):
        return None
    out = {"env": {}, "goodput": [], "handshakes": []}
    env = os.path.join(d, "env.txt")
    if os.path.isfile(env):
        for line in open(env, encoding="utf-8"):
            for key in ("date", "commit"):
                if line.startswith(key + ":") and key not in out["env"]:
                    out["env"][key] = line.split(":", 1)[1].split(" (")[0].strip()   # without the remark in parentheses
    import csv
    gp = os.path.join(d, "goodput.csv")
    if os.path.isfile(gp):
        groups = {}
        for r in csv.DictReader(open(gp, encoding="utf-8")):
            g = groups.setdefault((r["server"], r["client"], r["measurement"]), {"ok": [], "runs": 0})
            g["runs"] += 1
            if r.get("ok") == "1" and r.get("kbps"):
                g["ok"].append(float(r["kbps"]))
        for (s, c, meas), g in sorted(groups.items()):
            out["goodput"].append({"server": s, "client": c, "measurement": meas, "runs": g["runs"], "ok": len(g["ok"]),
                                   "median_kbps": median(g["ok"])})
    hs = os.path.join(d, "handshakes.csv")
    if os.path.isfile(hs):
        groups = {}
        for r in csv.DictReader(open(hs, encoding="utf-8")):
            groups.setdefault((r["server"], r["client"]), []).append(float(r["hs_per_s"]))
        for (s, c), v in sorted(groups.items()):
            out["handshakes"].append({"server": s, "client": c, "runs": len(v), "median": median(v)})
    return out


def fuzz_model(src, targets_file, fuzz_meta, stats_dir, records):
    if targets_file and os.path.isfile(targets_file):
        targets = [t.strip() for t in open(targets_file, encoding="utf-8") if t.strip()]
    else:
        targets = []
    corpus_root = os.path.join(src, "tools", "fuzz", "corpus")
    corpus = {}
    if os.path.isdir(corpus_root):
        for t in sorted(os.listdir(corpus_root)):
            p = os.path.join(corpus_root, t)
            if os.path.isdir(p):
                files = [os.path.join(dd, f) for dd, _, fs in os.walk(p) for f in fs]
                corpus[t] = {"files": len(files), "bytes": sum(os.path.getsize(f) for f in files)}
    if not targets:
        targets = sorted(corpus)
    # every JVM lane runs the fuzz test classes; the macOS lane (apple) is the one whose regression step is named, the
    # others count only when it is missing
    regression = None
    for r in sorted(records, key=lambda r: r["lane"] != "apple"):
        if r.get("fuzz_regression"):
            regression = {"tests": r["fuzz_regression"]["tests"], "failed": r["fuzz_regression"]["failed"], "host": r["host"]}
            break
    campaign = None
    if fuzz_meta and os.path.isfile(fuzz_meta):
        meta = load_json(fuzz_meta)
        per = {}
        for f in sorted(glob.glob(os.path.join(stats_dir or "", "**", "stats.tsv"), recursive=True)) if stats_dir else []:
            for line in open(f, encoding="utf-8", errors="replace"):
                c = line.rstrip("\n").split("\t")
                if len(c) < 8 or not c[2].isdigit():
                    continue
                p = per.setdefault(c[1], {"slices": 0, "seconds": 0, "execs": 0, "cov": 0, "corpus": 0, "finding": False})
                p["slices"] += 1
                p["seconds"] += int(c[2])
                p["execs"] += int(c[3]) if c[3].isdigit() else 0
                p["cov"] = max(p["cov"], int(c[4]) if c[4].isdigit() else 0)
                p["corpus"] = int(c[6]) if c[6].isdigit() else p["corpus"]
                # the result names a finding's file: only whether there was one is shown (fuzz.yml keeps them private)
                p["finding"] |= c[7] not in ("ok", "load-timeout")
        campaign = {"run_id": meta.get("databaseId"), "sha": meta.get("headSha", ""), "date": meta.get("createdAt", ""),
                    "url": meta.get("url", ""), "conclusion": meta.get("conclusion", ""), "targets": per}
    return {"targets": targets, "corpus": corpus, "regression": regression, "campaign": campaign}


def perf_model(perf_meta, perf_dir, sha):
    if not perf_meta or not os.path.isfile(perf_meta):
        return None
    meta = load_json(perf_meta)
    cells = []
    for f in sorted(glob.glob(os.path.join(perf_dir or "", "**", "*.json"), recursive=True)) if perf_dir else []:
        try:
            r = load_json(f)
        except ValueError:
            continue
        servers, clients = r.get("servers") or [], r.get("clients") or []
        for ci, client in enumerate(clients):
            for si, server in enumerate(servers):
                idx = ci * len(servers) + si
                for cell in ((r.get("measurements") or [])[idx] if idx < len(r.get("measurements") or []) else []) or []:
                    m = re.match(r"^([0-9.]+)", cell.get("details") or "")
                    cells.append({"server": server, "client": client, "measurement": cell.get("name", ""),
                                  "result": cell.get("result", ""), "kbps": float(m.group(1)) if m else None})
    return {"run_id": meta.get("databaseId"), "sha": meta.get("headSha", ""), "date": meta.get("createdAt", ""),
            "url": meta.get("url", ""), "conclusion": meta.get("conclusion", ""), "this_commit": meta.get("headSha") == sha,
            "cells": cells}


def has_data(model):
    """CI results to show: a run and at least one of its records (after 30 days the artifacts are gone, the run is not)."""
    return model["run"] is not None and bool(model["lanes"])


def status_of(rows):
    if not rows:
        return "none"
    if any(r["status"] in ("fail", "error") for r in rows):
        return "fail"
    if all(r["status"] == "empty" for r in rows):
        return "empty"
    return "pass"


def build_model(args):
    meta, records = load_ci(args.meta, args.data, args.sha)
    pairs = load_pairs(args.pairs)
    results = [r for rec in records for r in rec["results"]]
    compiled = [c for rec in records for c in rec["compiled"]]
    platforms = []
    for t in TARGETS:
        rows = [r for r in results if r["target"] == t]
        hosts = []
        for h in sorted({r["host"] for r in rows}):
            hr = [r for r in rows if r["host"] == h]
            hosts.append({"host": h, "modules": len(hr), "tests": sum(r["tests"] for r in hr),
                          "passed": sum(r["passed"] for r in hr), "failed": sum(r["failed"] for r in hr),
                          "skipped": sum(r["skipped"] for r in hr), "status": status_of(hr),
                          "problems": sorted(r["module"] for r in hr if r["status"] in ("fail", "error"))})
        comp = [c for c in compiled if c["target"] == t]
        status = status_of(rows) if rows else ("compiled" if comp and all(c["outcome"] == "success" for c in comp)
                                               else "fail" if comp else "none")
        platforms.append({"target": t, "hosts": hosts, "compiled": comp, "status": status})
    # engine interop: the cases of the engine-interop module, mapped to pairs
    cells = {}
    unmapped = []
    for rec in records:
        for c in rec["cases"]:
            p = pair_of(pairs, c["class"], c["name"])
            if not p:
                unmapped.append(c)
                continue
            cell = cells.setdefault(p, {"client": p[0], "server": p[1], "wire": p[2], "tests": 0, "passed": 0, "failed": 0,
                                        "skipped": 0, "failures": []})
            cell["tests"] += 1
            key = {"pass": "passed", "fail": "failed", "skip": "skipped"}[c["outcome"]]
            cell[key] += 1
            if c["outcome"] == "fail":
                cell["failures"].append(f"{c['class']}.{c['name']}")
    interop = sorted(cells.values(), key=lambda c: (c["client"], c["server"], c["wire"]))
    for c in interop:
        c["status"] = "fail" if c["failed"] else "pass" if c["passed"] else "empty"
    conformance = [c for rec in records for c in rec["conformance"]]
    runner = {}
    for rec in records:
        for cell in rec["interop_runner"]:
            ours = cell["server"] if cell["server"].startswith("kuicksilver") else cell["client"]
            peer = cell["client"] if ours == cell["server"] else cell["server"]
            role = "server" if ours == cell["server"] else "client"
            r = runner.setdefault((cell["image"], peer, role), {"image": cell["image"], "peer": peer, "role": role,
                                                                 "succeeded": 0, "failed": 0, "unsupported": 0, "failures": []})
            res = cell["result"]
            if res == "succeeded":
                r["succeeded"] += 1
            elif res == "unsupported":
                r["unsupported"] += 1
            else:
                r["failed"] += 1
                r["failures"].append(cell["case"])
    sizes = [s for rec in records for s in rec["sizes"]]
    return {
        "sha": args.sha,
        "version": args.version,
        "dir": args.dir or args.version,
        # a development snapshot of a commit on main (/dev/): its commit date; None for a release
        "snapshot": {"sha": args.sha, "date": args.snapshot_date} if args.dir == "dev" else None,
        "ref": args.ref,
        "run": None if meta is None else {"id": meta.get("databaseId"), "date": meta.get("createdAt", ""),
                                          "url": meta.get("url", ""), "event": meta.get("event", "")},
        "lanes": sorted(rec["lane"] for rec in records),
        "platforms": platforms,
        "interop": interop,
        "unmapped": unmapped,
        "conformance": conformance,
        "runner": sorted(runner.values(), key=lambda r: (r["image"], r["peer"], r["role"])),
        "fuzz": fuzz_model(args.src, args.fuzz_targets, args.fuzz_meta, args.fuzz_stats, records),
        "sizes": sizes,
        "perf": perf_model(args.perf_meta, args.perf, args.sha),
        "benchmarks": benchmarks_summary(args.src),
        "rfc": rfc_summary(os.path.join(args.src, "docs", "spec", "rfc-compliance.md")),
        "process": process_anchors(args.src),
        "schema": MODEL_SCHEMA,
    }


# -------------------------------------------------------------------------------------------------------------- badges

def badge(label, value, color):
    """A flat badge in the shields.io layout; the width is estimated from the text (Verdana 11px, about 6.5 px a char)."""
    lw = int(len(label) * 6.5) + 12
    vw = int(len(value) * 6.5) + 12
    w = lw + vw
    e = html.escape
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="20" role="img" aria-label="{e(label)}: {e(value)}">'
        f"<title>{e(label)}: {e(value)}</title>"
        f'<rect width="{lw}" height="20" fill="#555"/><rect x="{lw}" width="{vw}" height="20" fill="{color}"/>'
        '<g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11">'
        f'<text x="{lw / 2}" y="14">{e(label)}</text><text x="{lw + vw / 2}" y="14">{e(value)}</text></g></svg>\n'
    )


GREEN, RED, GREY, AMBER = "#2da44e", "#cf222e", "#6e7781", "#bf8700"


def badges(model):
    """Language-independent badges (English labels, as on every README)."""
    out = {}
    if not has_data(model):
        out["tests"] = badge("test runs", "no data", GREY)
        out["platforms"] = badge("platforms", "no data", GREY)
        out["engine-interop"] = badge("engine interop", "no data", GREY)
    else:
        passed = sum(h["passed"] for p in model["platforms"] for h in p["hosts"])
        failed = sum(h["failed"] for p in model["platforms"] for h in p["hosts"])
        # every test run of every CI host: a JVM test that runs on five hosts counts five times (the platform page says so)
        out["tests"] = badge("test runs", f"{passed} passed" + (f", {failed} failed" if failed else ""),
                             RED if failed else GREEN if passed else GREY)
        ok = sum(1 for p in model["platforms"] if p["status"] in ("pass", "compiled"))
        bad = any(p["status"] == "fail" for p in model["platforms"])
        out["platforms"] = badge("platforms", f"{ok}/{len(TARGETS)} green", RED if bad else GREEN if ok == len(TARGETS) else AMBER)
        good = sum(1 for c in model["interop"] if c["status"] == "pass")
        out["engine-interop"] = badge("engine interop", f"{good}/{len(model['interop'])} pairs" if model["interop"] else "no data",
                                      RED if good < len(model["interop"]) else GREEN if model["interop"] else GREY)
    rfc = model["rfc"]
    out["rfc"] = (badge("RFC", f"{rfc['total']['✅']} met, {rfc['total']['🔶']} partial", GREEN if not rfc["total"]["🔶"] else AMBER)
                  if rfc else badge("RFC", "no data", GREY))
    return out


# --------------------------------------------------------------------------------------------------------------- pages

def esc(x):
    return html.escape(str(x))


def num(n):
    return f"{n:,}".replace(",", " ") if isinstance(n, int) else esc(n)


def kib(b):
    return f"{b / 1024:,.1f}".replace(",", " ") + " KiB"


def short(sha):
    return sha[:12] if sha else ""


def date_of(ts):
    return ts.replace("T", " ").rstrip("Z")[:16] + " UTC" if ts else ""


def mark(m, status):
    cls = {"pass": "pass", "compiled": "pass", "fail": "fail", "error": "fail", "empty": "warn", "none": "nodata"}.get(status, "nodata")
    return f'<span class="{cls}">{esc(m("status." + status))}</span>'


def gh(model, path):
    return f"{REPO_URL}/blob/{model['ref']}/{path}"


def table(head, rows, nums=()):
    th = "".join(f'<th{" class=num" if i in nums else ""}>{h}</th>' for i, h in enumerate(head))
    body = "".join("<tr>" + "".join(f'<td{" class=num" if i in nums else ""}>{c}</td>' for i, c in enumerate(r)) + "</tr>"
                   for r in rows)
    return f"<table><thead><tr>{th}</tr></thead><tbody>{body}</tbody></table>"


def nodata(m, key="nodata.run"):
    return f'<p class="nodata">{esc(m(key))}</p>'


def provenance(m, model):
    if model["run"] is None:
        return f'<p class="prov">{esc(m("prov.none", sha=model["sha"]))}</p>'
    r = model["run"]
    if not has_data(model):
        return (f'<p class="prov">{esc(m("prov.expired", sha=model["sha"], date=date_of(r["date"])))} '
                f'<a href="{esc(r["url"])}">{esc(m("prov.link", id=r["id"]))}</a></p>')
    return (f'<p class="prov">{esc(m("prov.run", sha=model["sha"], date=date_of(r["date"])))} '
            f'<a href="{esc(r["url"])}">{esc(m("prov.link", id=r["id"]))}</a></p>')


def page_index(m, model, rel_badges):
    imgs = "".join(f'<img src="{rel_badges}{n}.svg" alt="{esc(n)}">' for n in ("tests", "platforms", "engine-interop", "rfc"))
    rows = []
    for p in PAGES[1:]:
        rows.append([f'<a href="{p}.html">{esc(m("page." + p))}</a>', esc(m("lead." + p))])
    return (f"<h1>{esc(m('page.index'))}</h1>\n{provenance(m, model)}\n<p class=badges>{imgs}</p>\n"
            f"<p>{esc(m('index.intro'))}</p>\n" + table([esc(m("col.section")), esc(m("col.what"))], rows))


def page_platforms(m, model):
    if not has_data(model):
        return nodata(m)
    rows = []
    for p in model["platforms"]:
        if p["hosts"]:
            for h in p["hosts"]:
                problems = (" " + esc(m("platforms.problems", modules=", ".join(h["problems"])))) if h["problems"] else ""
                rows.append([f"<code>{esc(p['target'])}</code>", esc(h["host"]), num(h["modules"]), num(h["tests"]),
                             num(h["passed"]), num(h["failed"]), num(h["skipped"]), mark(m, h["status"]) + problems])
        elif p["compiled"]:
            for c in p["compiled"]:
                st = "compiled" if c["outcome"] == "success" else "fail"
                rows.append([f"<code>{esc(p['target'])}</code>", esc(c["host"]), "", "", "", "", "",
                             mark(m, st) + " " + esc(m("platforms.compiledOnly"))])
        else:
            rows.append([f"<code>{esc(p['target'])}</code>", "", "", "", "", "", "", mark(m, "none")])
    head = [m("col.target"), m("col.where"), m("col.modules"), m("col.tests"), m("col.passed"), m("col.failed"),
            m("col.skipped"), m("col.status")]
    return (f"<p>{esc(m('platforms.intro'))}</p>\n" + table([esc(h) for h in head], rows, nums=(2, 3, 4, 5, 6)) +
            f'\n<p class="note">{esc(m("platforms.note"))}</p>')


def page_interop(m, model):
    out = [f"<p>{esc(m('interop.intro'))} <a href=\"{gh(model, 'docs/spec/interop.md')}\">docs/spec/interop.md</a></p>"]
    if not has_data(model):
        out.append(nodata(m))
    elif not model["interop"]:
        out.append(nodata(m, "nodata.lane"))
    else:
        clients = sorted({c["client"] for c in model["interop"]})
        servers = sorted({c["server"] for c in model["interop"]})
        grid = []
        for cl in clients:
            row = [esc(cl)]
            for sv in servers:
                here = [c for c in model["interop"] if c["client"] == cl and c["server"] == sv]
                row.append(" ".join(f'<span class="{"pass" if c["status"] == "pass" else "fail" if c["status"] == "fail" else "warn"}">'
                                    f'{esc(c["wire"])} {"✓" if c["status"] == "pass" else "✗" if c["status"] == "fail" else "?"}</span>'
                                    for c in here) or "—")
            grid.append(row)
        out.append(f"<h2>{esc(m('interop.grid'))}</h2>")
        out.append(table([esc(m("col.clientServer"))] + [esc(s) for s in servers], grid))
        out.append(f"<h2>{esc(m('interop.pairs'))}</h2>")
        rows = [[esc(c["client"]), esc(c["server"]), esc(c["wire"]), num(c["tests"]), num(c["passed"]), num(c["failed"]),
                 num(c["skipped"]), mark(m, c["status"]) + ("<br><small>" + esc(", ".join(c["failures"])) + "</small>" if c["failures"] else "")]
                for c in model["interop"]]
        out.append(table([esc(m(k)) for k in ("col.client", "col.server", "col.wire", "col.tests", "col.passed", "col.failed",
                                              "col.skipped", "col.status")], rows, nums=(3, 4, 5, 6)))
        if model["unmapped"]:
            out.append(f'<p class="warn">{esc(m("interop.unmapped", n=len(model["unmapped"])))}</p>')
    out.append(f"<h2>{esc(m('interop.runner'))}</h2>")
    if model["runner"]:
        rows = [[esc(r["image"]), esc(r["peer"]), esc(m("role." + r["role"])), num(r["succeeded"]), num(r["failed"]),
                 num(r["unsupported"]), (mark(m, "fail") + " <small>" + esc(", ".join(r["failures"])) + "</small>") if r["failed"] else mark(m, "pass")]
                for r in model["runner"]]
        out.append(table([esc(m(k)) for k in ("col.image", "col.peer", "col.role", "col.succeeded", "col.failed",
                                              "col.unsupported", "col.status")], rows, nums=(3, 4, 5)))
    else:
        out.append(nodata(m, "interop.runnerNone"))
    return "\n".join(out)


def page_conformance(m, model):
    rows = []
    h2 = [c for c in model["conformance"] if c["suite"] == "h2spec"]
    for variant in ("tls", "h2c"):
        mine = [c for c in h2 if c["variant"] == variant]
        if mine:
            for c in mine:
                rows.append([f"h2spec ({esc(variant)})", esc(c["host"]), num(c["tests"]), num(c["passed"]), num(c["skipped"]),
                             num(c["failed"]), mark(m, c["status"])])
        else:
            rows.append([f"h2spec ({esc(variant)})", "", "", "", "", "", f'<span class="nodata">{esc(m("conformance.notInCi"))}</span>'])
    for suite in ("h3spec", "Autobahn"):
        rows.append([esc(suite), "", "", "", "", "", f'<span class="nodata">{esc(m("conformance.notYet"))}</span>'])
    return (f"<p>{esc(m('conformance.intro'))}</p>\n" +
            table([esc(m(k)) for k in ("col.suite", "col.where", "col.tests", "col.passed", "col.skipped", "col.failed", "col.status")],
                  rows, nums=(2, 3, 4, 5)) +
            f'\n<p class="note">{esc(m("conformance.local"))} <a href="{gh(model, "docs/spec/interop.md")}">docs/spec/interop.md</a></p>')


def page_fuzzing(m, model):
    f = model["fuzz"]
    out = [f"<p>{esc(m('fuzzing.intro', targets=len(f['targets'])))}</p>"]
    reg = f["regression"]
    out.append(f"<h2>{esc(m('fuzzing.regression'))}</h2>")
    if reg:
        out.append(f"<p>{esc(m('fuzzing.regressionCount', tests=reg['tests'], failed=reg['failed']))} "
                   f"{mark(m, 'fail' if reg['failed'] else 'pass')}</p>")
    else:
        out.append(nodata(m))
    out.append(f"<h2>{esc(m('fuzzing.targets'))}</h2>")
    camp = f["campaign"]
    rows = []
    for t in f["targets"]:
        c = f["corpus"].get(t)
        ct = camp["targets"].get(t) if camp else None
        rows.append([f"<code>{esc(t)}</code>", num(c["files"]) if c else "—", kib(c["bytes"]) if c else "—",
                     f"{ct['seconds'] / 3600:.1f}" if ct else "—", num(ct["execs"]) if ct else "—", num(ct["cov"]) if ct else "—",
                     (mark(m, "fail") if ct["finding"] else mark(m, "pass")) if ct else "—"])
    out.append(table([esc(m(k)) for k in ("col.fuzzTarget", "col.corpusFiles", "col.corpusSize", "col.hours", "col.execs",
                                          "col.coverage", "col.findings")], rows, nums=(1, 2, 3, 4, 5)))
    if camp:
        key = "fuzzing.campaignThis" if camp["sha"] == model["sha"] else "fuzzing.campaignOther"
        out.append(f'<p class="note">{esc(m(key, sha=short(camp["sha"]), date=date_of(camp["date"]), conclusion=camp["conclusion"]))} '
                   f'<a href="{esc(camp["url"])}">{esc(m("prov.link", id=camp["run_id"]))}</a></p>')
    else:
        out.append(nodata(m, "fuzzing.noCampaign"))
    out.append(f"<h2>{esc(m('fuzzing.mutation'))}</h2>\n" + nodata(m, "fuzzing.mutationNone"))
    return "\n".join(out)


def page_sizes(m, model):
    s = model["sizes"]
    out = [f"<p>{esc(m('sizes.intro'))}</p>"]
    if not has_data(model):
        return "\n".join(out + [nodata(m)])
    groups = [("sizes.android", [x for x in s if x["kind"] in ("aar", "aar-so")]),
              ("sizes.jni", [x for x in s if x["kind"] in ("jni", "jar")])]
    for key, items in groups:
        out.append(f"<h2>{esc(m(key))}</h2>")
        if items:
            out.append(table([esc(m("col.file")), esc(m("col.platform")), esc(m("col.size"))],
                             [[f"<code>{esc(x['name'])}</code>", esc(x["target"]), kib(x["bytes"])] for x in items], nums=(2,)))
        else:
            out.append(nodata(m, "nodata.lane"))
    out.append(f"<h2>{esc(m('sizes.klib'))}</h2>")
    kl = [x for x in s if x["kind"] == "klib"]
    if kl:
        rows = []
        for t in sorted({x["target"] for x in kl}):
            mine = [x for x in kl if x["target"] == t]
            rows.append([f"<code>{esc(t)}</code>", num(len(mine)), kib(sum(x["bytes"] for x in mine))])
        out.append(table([esc(m("col.target")), esc(m("col.modules")), esc(m("col.size"))], rows, nums=(1, 2)))
    else:
        out.append(nodata(m, "nodata.lane"))
    out.append(f"<h2>{esc(m('sizes.ios'))}</h2>")
    ios = [x for x in s if x["kind"] == "framework" or (x["kind"] == "zip" and "xcframework" in x["name"])]
    if ios:
        out.append(table([esc(m("col.file")), esc(m("col.platform")), esc(m("col.size"))],
                         [[f"<code>{esc(x['name'])}</code>", esc(x["target"]), kib(x["bytes"])] for x in ios], nums=(2,)))
        out.append(f'<p class="note">{esc(m("sizes.iosNote"))}</p>')
    else:
        out.append(nodata(m, "sizes.iosNone"))
    return "\n".join(out)


def page_benchmarks(m, model):
    out = [f"<p>{esc(m('benchmarks.intro'))} <a href=\"{gh(model, 'docs/benchmarks.md')}\">docs/benchmarks.md</a></p>",
           f"<h2>{esc(m('benchmarks.perf'))}</h2>"]
    p = model["perf"]
    if p and p["this_commit"] and p["cells"]:
        out.append(table([esc(m(k)) for k in ("col.server", "col.client", "col.measurement", "col.status", "col.kbps")],
                         [[esc(c["server"]), esc(c["client"]), esc(c["measurement"]),
                           mark(m, "pass" if c["result"] == "succeeded" else "fail"), num(int(c["kbps"])) if c["kbps"] else "—"]
                          for c in p["cells"]], nums=(4,)))
        cls = "" if p["conclusion"] == "success" else ' class="warn"'
        out.append(f'<p class="prov"><span{cls}>{esc(m("benchmarks.perfConclusion", id=p["run_id"], conclusion=p["conclusion"]))}</span> '
                   f'<a href="{esc(p["url"])}">{esc(m("prov.link", id=p["run_id"]))}</a></p>')
    else:
        out.append(nodata(m, "benchmarks.perfNone"))
    b = model["benchmarks"]
    out.append(f"<h2>{esc(m('benchmarks.committed'))}</h2>")
    if not b or not (b["goodput"] or b["handshakes"]):
        out.append(nodata(m, "benchmarks.committedNone"))
        return "\n".join(out)
    out.append(f'<p class="note">{esc(m("benchmarks.committedNote", date=b["env"].get("date", "?"), sha=short(b["env"].get("commit", ""))))}'
               f' <a href="{gh(model, "docs/benchmarks/env.txt")}">docs/benchmarks/env.txt</a></p>')
    if b["goodput"]:
        out.append(f"<h3>{esc(m('benchmarks.goodput'))}</h3>")
        out.append(table([esc(m(k)) for k in ("col.server", "col.client", "col.measurement", "col.runs", "col.kbps")],
                         [[esc(g["server"]), esc(g["client"]), esc(g["measurement"]), f"{g['ok']}/{g['runs']}",
                           num(int(g["median_kbps"])) if g["median_kbps"] is not None else "—"] for g in b["goodput"]], nums=(3, 4)))
    if b["handshakes"]:
        out.append(f"<h3>{esc(m('benchmarks.handshakes'))}</h3>")
        out.append(table([esc(m(k)) for k in ("col.server", "col.client", "col.runs", "col.hsPerS")],
                         [[esc(h["server"]), esc(h["client"]), num(h["runs"]), f"{h['median']:.0f}"] for h in b["handshakes"]],
                         nums=(2, 3)))
    return "\n".join(out)


def page_rfc(m, model):
    r = model["rfc"]
    link = f'<a href="{gh(model, "docs/spec/rfc-compliance.md")}">docs/spec/rfc-compliance.md</a>'
    if not r:
        return nodata(m, "rfc.none") + f"<p>{link}</p>"
    rows = [[esc(s)] + [num(c[k]) for k in STATUS] for s, c in r["sections"].items()]
    rows.append([f"<strong>{esc(m('rfc.total'))}</strong>"] + [f"<strong>{num(r['total'][k])}</strong>" for k in STATUS])
    out = [f"<p>{esc(m('rfc.intro'))} {link}</p>",
           table([esc(m("col.area"))] + [f"{k} {esc(m('rfc.status.' + str(i)))}" for i, k in enumerate(STATUS)], rows,
                 nums=(1, 2, 3, 4)),
           f"<h2>{esc(m('rfc.open'))}</h2>"]
    if r["open"]:
        out.append(table([esc(m(k)) for k in ("col.rfc", "col.topic", "col.status", "col.details")],
                         [[esc(o["rfc"]), esc(o["topic"]), o["status"],
                           f'<a href="{esc(gh(model, "docs/spec/" + o["details"]))}">{esc(m("rfc.details"))}</a>' if o["details"] else ""]
                          for o in r["open"]]))
    else:
        out.append(f"<p>{esc(m('rfc.noOpen'))}</p>")
    return "\n".join(out)


PROCESS_SECTIONS = ["1. A test that fails before the fix", "2. Review: the code and the RFC text",
                    "4. The RFC compliance matrix and the threat model", "5. Integration and the local gate", "6. Hosted CI",
                    "7. Before a release: soak, fuzzing, benchmarks", "8. The release"]


def process_anchors(src):
    """The GitHub anchor of each of PROCESS_SECTIONS in the published commit's docs/process.md; "" for a heading it no
    longer has (the link then goes to the top of the document instead of to a missing anchor)."""
    path = os.path.join(src, "docs", "process.md")
    heads = set()
    if os.path.isfile(path):
        heads = {line.lstrip("#").strip() for line in open(path, encoding="utf-8") if line.startswith("## ")}
    return ["#" + site.slug(s) if s in heads else "" for s in PROCESS_SECTIONS]


def page_how(m, model):
    items = "".join(f'<li><a href="{gh(model, "docs/process.md")}{a}">{esc(m("how.step" + str(i)))}</a></li>'
                    for i, a in enumerate(model["process"]))
    return (f"<p>{esc(m('how.intro'))}</p>\n<ol>{items}</ol>\n"
            f"<p>{esc(m('how.release'))} <a href=\"{gh(model, 'docs/verifying.md')}\">docs/verifying.md</a></p>\n"
            f'<p class="note">{esc(m("how.source"))} <a href="{gh(model, "docs/process.md")}">docs/process.md</a></p>')


def render(model, langs, out, base_url):
    renderers = {"platforms": page_platforms, "interop": page_interop, "conformance": page_conformance,
                 "fuzzing": page_fuzzing, "sizes": page_sizes, "benchmarks": page_benchmarks, "rfc": page_rfc, "how": page_how}
    written = []
    for code, m in langs.items():
        root = i18n.up(m.prefix + "verify/x.html")
        rel_badges = root + "verify/badges/"
        for p in PAGES:
            rel = f"verify/{p}.html" if p != "index" else "verify/index.html"
            nav = '<nav class="pages"><ul>' + "".join(
                f'<li{" class=current" if q == p else ""}><a href="{q}.html">{esc(m("page." + q))}</a></li>' for q in PAGES) + "</ul></nav>"
            if p == "index":
                body = page_index(m, model, rel_badges)
            else:
                body = f"<h1>{esc(m('page.' + p))}</h1>\n" + (provenance(m, model) if p not in ("rfc", "how") else "") + renderers[p](m, model)
            if code != i18n.DEFAULT:
                en = root + rel
                body = f'<p class="note">{esc(m("lang.unreviewed"))} <a href="{en}" hreflang="en" lang="en">English</a></p>\n' + body
            title = f"{m('page.' + p)} - Kuicksilver {model['version']}"
            path = os.path.join(out, m.prefix + rel)
            banner = ""
            if model.get("snapshot"):
                sn = model["snapshot"]
                banner = (f'<div class="snapshot" role="note">{esc(m("dev.banner", sha=sn["sha"], date=sn["date"]))} '
                          f'<a href="{root}../index.html">{esc(m("dev.releases"))}</a></div>\n')
            site.write(path, i18n.shell(m, rel, title, body, langs, base_url, STYLE, nav, banner))
            written.append(path)
    for name, svg in badges(model).items():
        site.write(os.path.join(out, "verify", "badges", name + ".svg"), svg)
    site.write(os.path.join(out, "verify", "data.json"), json.dumps(model, indent=1, sort_keys=True, ensure_ascii=False) + "\n")
    return written


def build(args):
    if not SHA.match(args.sha):
        sys.exit(f"verify.py build: '{args.sha}' is not a commit SHA")
    try:
        langs = i18n.load(args.messages)
        model = build_model(args)
    except Refused as e:
        print(f"verify.py build: refused: {e}", file=sys.stderr)
        return 1
    except i18n.MessageError as e:
        print(f"verify.py build: messages: {e}", file=sys.stderr)
        return 1
    if (args.dir == "dev") != bool(args.snapshot_date):
        sys.exit("verify.py build: --dir dev and --snapshot-date go together")
    if args.dir not in (None, "dev", args.version):
        sys.exit("verify.py build: --dir is the version or dev")
    base = args.base_url or f"{SITE_URL}{args.dir or args.version}/"
    try:
        written = render(model, langs, args.out, base)
    except i18n.MessageError as e:
        print(f"verify.py build: messages: {e}", file=sys.stderr)
        return 1
    print(f"verify.py build: {len(written)} pages in {len(langs)} languages; "
          f"{'run ' + str(model['run']['id']) if model['run'] else 'no build.yml run'}, lanes: {', '.join(model['lanes']) or 'none'}",
          file=sys.stderr)
    return 0


def _model_of(version_dir):
    try:
        return load_json(os.path.join(version_dir, "verify", "data.json"))
    except (OSError, ValueError):
        return None


def _note(text):
    # a warning annotation in the Actions log, plain text elsewhere
    print(("::warning::" if os.environ.get("GITHUB_ACTIONS") == "true" else "verify.py keep: ") + text, file=sys.stderr)


def keep(args):
    """Only the verify section is decided here; the rest of the version's site is published either way, and keep never
    fails for want of data. The new pages stay when they have CI data. Without it, the published pages of the same
    commit with data are kept: rendered again from their data.json in every language at once (no language mixed with
    no-data pages, and a language added since gets them too) when its schema is this one and the rendering succeeds;
    otherwise (an older or unknown schema, a rendering that fails) the published verify directories are kept exactly as
    they are, every language, with a warning: real data is never replaced by "no data". Only when no verification pages
    were published, or they have no data either, do the new "no data" pages go out."""
    import shutil
    import tempfile
    new = _model_of(args.new)
    if new is None:
        print(f"verify.py keep: {args.new} has no verify/data.json", file=sys.stderr)
        return 1
    if new.get("lanes"):
        print(f"verify.py keep: the new pages have CI data ({len(new['lanes'])} lanes)", file=sys.stderr)
        return 0
    if not os.path.isdir(os.path.join(args.old, "verify")):
        _note(f"no CI data for {new.get('sha')} and no published verification pages: the pages say no data (run build.yml "
              "on the commit and publish the version again to fill them)")
        return 0
    old = _model_of(args.old)
    if old is not None and old.get("sha") not in (None, new.get("sha")):
        _note(f"the published verification pages are of {old.get('sha')}, not {new.get('sha')}: the new pages say no data")
        return 0
    langs = i18n.load(args.messages)
    if old is not None and old.get("schema") == MODEL_SCHEMA:
        if not old.get("lanes"):
            _note(f"no CI data for {new.get('sha')}, neither now nor in the published pages: the pages say no data")
            return 0
        tmp = tempfile.mkdtemp(prefix="verify-keep-")
        try:
            render(old, langs, tmp, args.base_url or f"{SITE_URL}{old['dir']}/")
        except Exception as e:   # any error of the old model with this code: the published pages stay as they are
            shutil.rmtree(tmp, ignore_errors=True)
            _note(f"the published data.json of {old.get('sha')} does not render with this verify.py ({type(e).__name__}: {e}): "
                  "its published verification pages are kept as they are")
        else:
            for m in langs.values():
                shutil.rmtree(os.path.join(args.new, m.prefix, "verify"), ignore_errors=True)
                shutil.copytree(os.path.join(tmp, m.prefix, "verify"), os.path.join(args.new, m.prefix, "verify"))
            shutil.rmtree(tmp, ignore_errors=True)
            print(f"verify.py keep: no CI data in the new pages; kept the published data of {old['sha']} ({len(old['lanes'])} "
                  f"lanes), rendered in all {len(langs)} languages", file=sys.stderr)
            return 0
    else:
        _note(f"the published verification pages have data.json schema {None if old is None else old.get('schema')}, this "
              f"verify.py reads {MODEL_SCHEMA}: they are kept as they are")
    # the published verify directories exactly as they are: every language they have, and none they do not (their own
    # language switch links only to those)
    for m in langs.values():
        dst = os.path.join(args.new, m.prefix, "verify")
        shutil.rmtree(dst, ignore_errors=True)
        src = os.path.join(args.old, m.prefix, "verify")
        if os.path.isdir(src):
            shutil.copytree(src, dst)
    return 0


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("collect")
    c.add_argument("--lane", required=True)
    c.add_argument("--host", required=True)
    c.add_argument("--out", required=True)
    c.add_argument("--sha")
    c.add_argument("--run-id")
    c.add_argument("--run-attempt")
    c.add_argument("--allow-empty", action="store_true", help="a source that matches nothing is not an error")
    for opt in ("--junit", "--cases", "--gtest", "--compiled", "--size", "--skip-module", "--h2spec-manifest", "--interop-runner"):
        c.add_argument(opt, action="append")
    b = sub.add_parser("build")
    b.add_argument("--sha", required=True)
    b.add_argument("--version", required=True)
    b.add_argument("--ref", required=True)
    b.add_argument("--src", required=True)
    b.add_argument("--out", required=True)
    b.add_argument("--meta")
    b.add_argument("--data")
    b.add_argument("--fuzz-meta")
    b.add_argument("--fuzz-stats")
    b.add_argument("--fuzz-targets")
    b.add_argument("--perf-meta")
    b.add_argument("--perf")
    b.add_argument("--base-url")
    b.add_argument("--dir", help="the directory the pages are for: the version (default) or dev, a development snapshot")
    b.add_argument("--snapshot-date", help="with --dir dev: the commit date shown in the snapshot banner")
    b.add_argument("--messages", default=os.path.join(HERE, "messages"))
    b.add_argument("--pairs", default=os.path.join(HERE, "engine-pairs.tsv"))
    k = sub.add_parser("keep")
    k.add_argument("--new", required=True)
    k.add_argument("--old", required=True)
    k.add_argument("--base-url")
    k.add_argument("--messages", default=os.path.join(HERE, "messages"))
    p = sub.add_parser("check-pairs")
    p.add_argument("--sources", required=True)
    p.add_argument("--pairs", default=os.path.join(HERE, "engine-pairs.tsv"))
    args = ap.parse_args()
    if args.cmd == "collect":
        return collect(args)
    if args.cmd == "keep":
        return keep(args)
    if args.cmd == "check-pairs":
        return check_pairs(args.sources, args.pairs)
    return build(args)


if __name__ == "__main__":
    sys.exit(main())
