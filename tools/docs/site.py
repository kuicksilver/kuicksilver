# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
"""Documentation site builder, called by tools/docs/site.sh (read its header first).

  site.py build --version V --ref R --api DIR --guide DIR --out OUT
      OUT/V/api/     a copy of the Dokka HTML in DIR
      OUT/V/guide/   DIR/*.md rendered to HTML (markdown-it-py, tools/docs/requirements.txt)
      OUT/index.html the landing page, OUT/latest/ a copy of the newest release; both recomputed from every version in OUT,
                     so building into a copy of the published site adds a version and keeps the others
  site.py index OUT  only the landing page and OUT/latest/, from the versions already in OUT (the Pages workflow, after it
                     put a newly built version into the published site)
  site.py check OUT [--version V --baseline FILE [--undocumented FILE] [--sources REPO]]
                     every relative link and image of the landing and guide pages under OUT must resolve to a file (and,
                     into a guide page, to one of its anchors); exit 1 with one line per broken link. Broken links inside
                     the Dokka output are listed on stderr; with --baseline, their number in OUT/V/api and the number of
                     undocumented declarations must equal the baseline, and with --sources no top-level
                     @InternalKuicksilverApi declaration of the sources may have a page; an ERROR CLASS in an API
                     page fails it
"""
import argparse
import html
import os
import posixpath
import re
import shutil
import sys
import unicodedata
from html.parser import HTMLParser
from urllib.parse import unquote

REPO = "https://github.com/kuicksilver/kuicksilver"
VERSION = re.compile(r"^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.]+))?$")
# reading order of the guide index; a page not listed here follows in file name order
GUIDE_ORDER = ["quic", "http3", "tls", "ktor", "deployment", "ios", "app-store", "configuration", "troubleshooting"]
SCHEME = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*:")

STYLE = """
:root { --bg: #ffffff; --fg: #1f2328; --muted: #59636e; --line: #d1d9e0; --code: #f6f8fa; --link: #0969da; }
@media (prefers-color-scheme: dark) {
  :root { --bg: #0d1117; --fg: #e6edf3; --muted: #9198a1; --line: #3d444d; --code: #151b23; --link: #4493f8; }
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--fg); font: 16px/1.6 -apple-system, BlinkMacSystemFont, "Segoe UI",
  "Noto Sans", Helvetica, Arial, sans-serif; }
a { color: var(--link); }
header { border-bottom: 1px solid var(--line); padding: 12px 16px; display: flex; gap: 16px; flex-wrap: wrap; align-items: baseline; }
header .name { font-weight: 600; color: var(--fg); text-decoration: none; }
header .version { color: var(--muted); }
.layout { display: flex; max-width: 1280px; margin: 0 auto; }
nav.pages { flex: 0 0 220px; padding: 16px; border-right: 1px solid var(--line); }
nav.pages ul { list-style: none; padding: 0; margin: 0; }
nav.pages li { margin: 4px 0; }
nav.pages .current { font-weight: 600; }
main { flex: 1 1 auto; min-width: 0; padding: 16px 32px 48px; }
pre, code { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 85%; }
pre { background: var(--code); padding: 12px 16px; overflow-x: auto; border-radius: 6px; }
:not(pre) > code { background: var(--code); padding: 0.1em 0.3em; border-radius: 4px; }
table { border-collapse: collapse; display: block; overflow-x: auto; }
th, td { border: 1px solid var(--line); padding: 6px 12px; vertical-align: top; }
blockquote { margin: 0; padding: 0 16px; color: var(--muted); border-left: 4px solid var(--line); }
li.task { list-style: none; }
h1, h2, h3 { line-height: 1.25; }
h2 { border-bottom: 1px solid var(--line); padding-bottom: 0.3em; }
@media (max-width: 760px) { .layout { display: block; } nav.pages { border-right: 0; border-bottom: 1px solid var(--line); }
  main { padding: 16px; } }
"""


def version_key(v):
    m = VERSION.match(v)
    major, minor, patch, pre = int(m.group(1)), int(m.group(2)), int(m.group(3)), m.group(4)
    # a final release sorts after its pre-releases (SemVer 11)
    return (major, minor, patch, pre is None, [(0, int(p), "") if p.isdigit() else (1, 0, p) for p in (pre or "").split(".")])


def slug(heading):
    """GitHub's heading anchor (the same rule as tools/check/links.sh): lower case, markup and punctuation dropped."""
    h = re.sub(r"`([^`]*)`", r"\1", heading)
    h = re.sub(r"!?\[([^\]]*)\]\([^)]*\)", r"\1", h)
    h = re.sub(r"<[^>]+>", "", h).strip().lower()
    out = []
    for ch in h:
        cat = unicodedata.category(ch)
        if ch in "-_ " or cat[0] in "LN" or cat == "Mn":
            out.append("-" if ch == " " else ch)
    return "".join(out)


def page(title, version, body, nav="", depth=2):
    up = "../" * depth
    links = f'<a href="{up}index.html">Home</a>'
    if version:
        links += f' <a href="../guide/index.html">Guide</a> <a href="../api/index.html">API reference</a>'
    return (
        "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
        f"<title>{html.escape(title)}</title>\n<style>{STYLE}</style>\n</head>\n<body>\n"
        f'<header><a class="name" href="{up}index.html">Kuicksilver</a>'
        + (f'<span class="version">{html.escape(version)}</span>' if version else "")
        + f"{links}</header>\n"
        + (f'<div class="layout">{nav}<main>\n{body}\n</main></div>' if nav else f"<main>\n{body}\n</main>")
        + "\n</body>\n</html>\n"
    )


def render_guide(src, dst, version, ref):
    from markdown_it import MarkdownIt

    md = MarkdownIt("commonmark", {"html": True}).enable(["table", "strikethrough"])
    names = sorted(f[:-3] for f in os.listdir(src) if f.endswith(".md"))
    names.sort(key=lambda n: (GUIDE_ORDER.index(n) if n in GUIDE_ORDER else len(GUIDE_ORDER), n))
    pages = {}
    for name in names:
        text = open(os.path.join(src, name + ".md"), encoding="utf-8").read()
        text = re.sub(r"\A<!--.*?-->\s*", "", text, flags=re.S)   # the licence header comment
        tokens = md.parse(text)
        title, seen = name, {}
        for i, tok in enumerate(tokens):
            if tok.type == "heading_open":
                inline = tokens[i + 1]
                base = slug(inline.content)
                k = seen.get(base, 0)
                seen[base] = k + 1
                tok.attrSet("id", base if k == 0 else f"{base}-{k}")
                if tok.tag == "h1" and title == name:
                    title = re.sub(r"`([^`]*)`", r"\1", inline.content)
            if tok.type == "inline":
                if i >= 2 and tokens[i - 1].type == "paragraph_open" and tokens[i - 2].type == "list_item_open":
                    task(tokens[i - 2], tok)
                for child in tok.children or []:
                    if child.type == "link_open":
                        child.attrSet("href", rewrite(child.attrGet("href"), src, names, ref))
                    elif child.type == "image":
                        child.attrSet("src", rewrite(child.attrGet("src"), src, names, ref, raw=True))
        pages[name] = (title, md.renderer.render(tokens, md.options, {}))
    os.makedirs(dst, exist_ok=True)

    def nav(current):
        mark = ' class="current"'
        items = "".join(
            f'<li{mark if n == current else ""}><a href="{n}.html">{html.escape(t)}</a></li>' for n, (t, _) in pages.items()
        )
        return f'<nav class="pages"><ul><li><a href="index.html">Guide</a></li>{items}</ul></nav>'

    for name, (title, body) in pages.items():
        write(os.path.join(dst, name + ".html"), page(f"{title} - Kuicksilver {version}", version, body, nav(name)))
    rows = "".join(f'<li><a href="{n}.html">{html.escape(t)}</a></li>' for n, (t, _) in pages.items())
    body = (f"<h1>Kuicksilver {html.escape(version)} guide</h1>\n<ul>{rows}</ul>\n"
            '<p>The <a href="../api/index.html">API reference</a> documents every public declaration.</p>')
    write(os.path.join(dst, "index.html"), page(f"Guide - Kuicksilver {version}", version, body, nav("index")))


def task(item_open, inline):
    """GitHub task list items: '[ ] ' / '[x] ' at the start of a list item becomes a disabled checkbox."""
    m = re.match(r"^\[([ xX])\] ", inline.content)
    if not m or not inline.children or inline.children[0].type != "text":
        return
    first = inline.children[0]
    first.content = first.content[4:]
    from markdown_it.token import Token

    box = Token("html_inline", "", 0)
    box.content = f'<input type="checkbox" disabled{" checked" if m.group(1) != " " else ""}> '
    inline.children.insert(0, box)
    item_open.attrSet("class", "task")


def rewrite(url, src, names, ref, raw=False):
    """Guide page links stay in the site (x.md -> x.html); other repository paths go to GitHub at the docs' ref."""
    if not url or url.startswith("#") or SCHEME.match(url):
        return url
    path, _, frag = url.partition("#")
    frag = "#" + frag if frag else ""
    target = posixpath.normpath(posixpath.join("docs/guide", path))
    if target.startswith("docs/guide/") and target.endswith(".md") and target[len("docs/guide/"):-3] in names:
        return target[len("docs/guide/"):-3] + ".html" + frag
    repo_root = os.path.normpath(os.path.join(src, "..", ".."))
    kind = "tree" if os.path.isdir(os.path.join(repo_root, target)) else "blob"
    return f"{REPO}/{kind}/{ref}/{target}{'?raw=true' if raw else ''}{frag}"


def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)


def landing(out):
    versions = sorted((d for d in os.listdir(out) if VERSION.match(d) and os.path.isdir(os.path.join(out, d))), key=version_key)
    if not versions:
        sys.exit(f"site.py: no version directory in {out}")
    finals = [v for v in versions if VERSION.match(v).group(4) is None]
    releases = [v for v in versions if not v.endswith("-SNAPSHOT")]
    latest = (finals or releases or versions)[-1]   # the newest final release; a pre-release or snapshot only without one
    tmp = os.path.join(out, ".latest.tmp")
    shutil.rmtree(tmp, ignore_errors=True)
    shutil.copytree(os.path.join(out, latest), tmp)
    shutil.rmtree(os.path.join(out, "latest"), ignore_errors=True)
    os.rename(tmp, os.path.join(out, "latest"))
    rows = "".join(
        f'<tr><td>{html.escape(v)}</td><td><a href="{v}/guide/index.html">Guide</a></td>'
        f'<td><a href="{v}/api/index.html">API reference</a></td></tr>' for v in reversed(versions)
    )
    body = (
        "<h1>Kuicksilver</h1>\n<p>QUIC, HTTP/3 and TLS 1.3 for Kotlin Multiplatform, with Ktor client and server engines.</p>\n"
        f"<h2>Latest release: {html.escape(latest)}</h2>\n"
        '<ul><li><a href="latest/guide/index.html">Guide</a>: QUIC, HTTP/3, TLS, the Ktor engines, deployment, '
        "configuration and troubleshooting</li>\n"
        '<li><a href="latest/api/index.html">API reference</a>: every public declaration of the published modules</li></ul>\n'
        f"<h2>All versions</h2>\n<table><tr><th>Version</th><th></th><th></th></tr>{rows}</table>\n"
        f'<p>Source code, releases and issues: <a href="{REPO}">{REPO}</a>.</p>'
    )
    write(os.path.join(out, "index.html"), page("Kuicksilver documentation", "", body, depth=0))
    write(os.path.join(out, ".nojekyll"), "")
    return latest


class Links(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links, self.ids = [], set()

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if "id" in a:
            self.ids.add(a["id"])
        if tag == "a" and "name" in a:
            self.ids.add(a["name"])
        for key in ("href", "src"):
            if a.get(key) and tag in ("a", "link", "script", "img", "iframe"):
                self.links.append(a[key])


def check(out, version=None, baseline=None, undocumented=None, sources=None):
    """Fails on a broken link of the site's own pages (landing, guide), links into the API reference included. Links
    inside the Dokka output come from the KDoc (a [name] that names a parameter or an internal member): they are listed,
    and with a baseline (tools/docs/api-baseline.properties) their number in OUT/<version>/api, the number of undocumented
    declarations are checked against it, and with the sources no @InternalKuicksilverApi declaration may have a page.
    A type Dokka could not resolve (ERROR CLASS) in an API page fails the check."""
    parsed, broken, api_broken = {}, [], []

    def parse(path):
        if path not in parsed:
            p = Links()
            p.feed(open(path, encoding="utf-8", errors="replace").read())
            parsed[path] = p
        return parsed[path]

    for d, _, files in os.walk(out):
        for f in sorted(files):
            if not f.endswith(".html"):
                continue
            path = os.path.join(d, f)
            rel = os.path.relpath(path, out).replace(os.sep, "/")
            into = api_broken if "/api/" in "/" + rel else broken
            if into is api_broken and "ERROR CLASS" in open(path, encoding="utf-8", errors="replace").read():
                broken.append((rel, "a type Dokka could not resolve (ERROR CLASS): its source set lacks a classpath"))
            for url in parse(path).links:
                if SCHEME.match(url) or url.startswith("//"):
                    continue
                target, _, frag = url.partition("#")
                target = unquote(target.partition("?")[0])
                dest = path if not target else os.path.normpath(os.path.join(d, target))
                if os.path.isdir(dest):
                    dest = os.path.join(dest, "index.html")
                if not os.path.isfile(dest):
                    into.append((rel, url))
                elif frag and "/guide/" in dest.replace(os.sep, "/") and dest.endswith(".html") and frag not in parse(dest).ids:
                    into.append((rel, f"{url} (no anchor #{frag})"))
    for rel, url in broken:
        print(f"broken link: {rel}: {url}")
    for rel, url in sorted(set(api_broken)):
        print(f"api reference (KDoc): broken link {rel}: {url}", file=sys.stderr)
    print(f"site.py check: {len(parsed)} pages, {len(broken)} broken links ({len(api_broken)} inside the API reference)",
          file=sys.stderr)
    failed = bool(broken)
    if baseline:
        failed |= ratchet(out, version, baseline, undocumented, api_broken, sources)
    return 1 if failed else 0


def dokka_name(name):
    """Dokka's file name of a class page: NullCryptoProvider -> -null-crypto-provider."""
    return re.sub(r"[A-Z]", lambda m: "-" + m.group(0).lower(), name)


ANNOTATION = re.compile(r"@(?:[\w.]+:)?([\w.]+)(?:\((?:[^()]|\([^()]*\))*\))?")
DECLARATION = re.compile(
    r"^(?P<mods>(?:(?:public|internal|private|protected|expect|actual|sealed|data|abstract|open|"
    r"enum|annotation|inline|value|const|operator|infix|suspend|fun(?= interface))\s+)*)"
    r"(?:class|object|interface|fun|val|var|typealias)\s+(?:<[^>]*>\s*)?(?:[\w.<>?, ]+?\.)?(?P<name>`?\w+`?)"
)


def internal_names(sources, modules):
    """(module, package, name) of the top-level declarations annotated @InternalKuicksilverApi in the main sources of the
    documented modules, but for names a public top-level declaration of the same package also has (one page for both)."""
    internal, public = set(), set()
    for module in modules:
        src = os.path.join(sources, module, "src")
        if not os.path.isdir(src):
            continue
        for main in sorted(d for d in os.listdir(src) if d.endswith("Main")):
            for d, _, files in os.walk(os.path.join(src, main)):
                for f in sorted(files):
                    if not f.endswith(".kt"):
                        continue
                    package, pending = "", False
                    for line in open(os.path.join(d, f), encoding="utf-8"):
                        if line.startswith("package "):
                            package = line.split()[1]
                            continue
                        if not line.strip() or line[0].isspace() or line.startswith(("//", "/*", " *", "*/", "import ")):
                            continue
                        # leading annotations, on their own lines or before the declaration
                        rest = line.rstrip()
                        while rest.startswith("@"):
                            m = ANNOTATION.match(rest)
                            pending |= m.group(1) == "InternalKuicksilverApi"
                            rest = rest[m.end():].lstrip()
                        if not rest:
                            continue
                        m = DECLARATION.match(rest)
                        if m and not re.search(r"\b(private|internal)\b", m.group("mods")):
                            (internal if pending else public).add((module, package, m.group("name").strip("`")))
                        pending = False
    return {x for x in internal if x not in public}


def limit(limits, key, baseline):
    if key not in limits:
        sys.exit(f"site.py: {baseline} has no '{key}=' line")
    try:
        return int(limits[key])
    except ValueError:
        sys.exit(f"site.py: {baseline}: '{key}={limits[key]}' is not a number")


def ratchet(out, version, baseline, undocumented, api_broken, sources):
    limits = {}
    for line in open(baseline, encoding="utf-8"):
        line = line.strip()
        if line and not line.startswith("#"):
            key, _, value = line.partition("=")
            limits[key.strip()] = value.strip()
    prefix = f"{version}/api/"
    counts = {"api-broken-links": len({b for b in api_broken if b[0].startswith(prefix)})}
    if undocumented is not None:
        counts["undocumented"] = len({x for x in open(undocumented, encoding="utf-8").read().split("\n") if x.strip()})
    failed = False
    for key, count in counts.items():
        allowed = limit(limits, key, baseline)
        if count > allowed:
            print(f"ratchet: {key} is {count}, above the baseline {allowed} ({baseline})")
            failed = True
        elif count < allowed:
            # the baseline follows every fix down in the same change, so it never leaves room for a new gap
            print(f"ratchet: {key} is {count}, below the baseline {allowed}: lower it to {count} in {baseline}")
            failed = True
        else:
            print(f"ratchet: {key} is {count} (baseline {allowed})", file=sys.stderr)
        if key == "undocumented" and count == 0 and allowed > 0:
            print("ratchet: no undocumented declaration was parsed: did Dokka run with -Pkuicksilver.docs.reportUndocumented?")
            failed = True
    api = os.path.join(out, version, "api")
    if sources:
        modules = sorted(d for d in os.listdir(api) if os.path.isdir(os.path.join(api, d)) and d.startswith("kuicksilver-"))
        names = internal_names(sources, modules)
        if not names:
            print(f"ratchet: no @InternalKuicksilverApi declaration found under {sources}")
            failed = True
        for module, package, name in sorted(names):
            page = os.path.join(api, module, package, dokka_name(name))
            if os.path.exists(page) or os.path.exists(page + ".html"):
                print(f"ratchet: {package}.{name} is @InternalKuicksilverApi but has a page: {os.path.relpath(page, out)}")
                failed = True
        print(f"ratchet: {len(names)} @InternalKuicksilverApi declarations, none with a page" if not failed else "", file=sys.stderr)
    return failed


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build")
    b.add_argument("--version", required=True)
    b.add_argument("--ref", required=True)
    b.add_argument("--api", required=True)
    b.add_argument("--guide", required=True)
    b.add_argument("--out", required=True)
    sub.add_parser("index").add_argument("out")
    c = sub.add_parser("check")
    c.add_argument("out")
    c.add_argument("--version", help="the version whose API reference the baseline applies to")
    c.add_argument("--baseline", help="tools/docs/api-baseline.properties")
    c.add_argument("--undocumented", help="one undocumented declaration per line (tools/docs/site.sh)")
    c.add_argument("--sources", help="the repository: its @InternalKuicksilverApi declarations must have no API page")
    args = ap.parse_args()
    if args.cmd == "check":
        if args.baseline and not args.version:
            sys.exit("site.py: check --baseline needs --version")
        return check(args.out, args.version, args.baseline, args.undocumented, args.sources)
    if args.cmd == "index":
        print(f"site.py: latest is {landing(args.out)}", file=sys.stderr)
        return 0
    if not VERSION.match(args.version):
        sys.exit(f"site.py: '{args.version}' is not a version (X.Y.Z or X.Y.Z-suffix)")
    target = os.path.join(args.out, args.version)
    shutil.rmtree(target, ignore_errors=True)
    shutil.copytree(args.api, os.path.join(target, "api"))
    render_guide(args.guide, os.path.join(target, "guide"), args.version, args.ref)
    latest = landing(args.out)
    print(f"site.py: {target} built; latest is {latest}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
