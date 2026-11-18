# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
"""The languages of the documentation site's generated pages (tools/docs/verify.py uses it; other generated sections can
use it the same way). English is the default and canonical language: its pages sit at the plain path, every other
language under /<prefix>/ of the same version directory (a page x/y.html in English is ru/x/y.html in Russian). The
label strings of each language are one JSON file in tools/docs/messages/; every file must have exactly the keys of
en.json, with the same {placeholders}, or loading fails (no page ever shows a blank or another language's label).

  load(messages_dir)            -> {code: Messages}, checked as above
  shell(lang, rel, title, body, langs, base_url)  one HTML page: lang attribute, hreflang alternates, language switch
"""
import html
import json
import os
import string

# code (BCP 47, the lang attribute and hreflang), path prefix ("" for the canonical language), message file, name in itself
LANGUAGES = [
    ("en", "", "en.json", "English"),
    ("ru", "ru/", "ru.json", "Русский"),
    ("zh-CN", "zh/", "zh-CN.json", "简体中文"),
]
DEFAULT = "en"


class MessageError(Exception):
    pass


class Messages:
    def __init__(self, code, prefix, name, table):
        self.code, self.prefix, self.name, self.table = code, prefix, name, table

    def __call__(self, key, **kw):
        if key not in self.table:
            raise MessageError(f"{self.code}: no message '{key}'")
        text = self.table[key]
        try:
            return text.format(**kw) if kw or "{" in text else text
        except (KeyError, IndexError) as e:
            raise MessageError(f"{self.code}: message '{key}' needs {e}") from e


def placeholders(text):
    return sorted({f for _, f, _, _ in string.Formatter().parse(text) if f})


def load(messages_dir):
    """Every language's messages; MessageError when a file is missing, is not a flat string table, lacks a key of en.json,
    has a key en.json lacks, or has other {placeholders} than the English text."""
    tables = {}
    for code, prefix, file, name in LANGUAGES:
        path = os.path.join(messages_dir, file)
        if not os.path.isfile(path):
            raise MessageError(f"no message file {file} for {code}")
        with open(path, encoding="utf-8") as f:
            table = json.load(f)
        if not isinstance(table, dict) or not all(isinstance(v, str) for v in table.values()):
            raise MessageError(f"{file}: not a flat object of strings")
        empty = sorted(k for k, v in table.items() if not v.strip())
        if empty:
            raise MessageError(f"{file}: empty messages: {', '.join(empty)}")
        tables[code] = Messages(code, prefix, name, table)
    base = tables[DEFAULT].table
    problems = []
    for code, m in tables.items():
        missing = sorted(set(base) - set(m.table))
        extra = sorted(set(m.table) - set(base))
        if missing:
            problems.append(f"{code}: missing keys: {', '.join(missing)}")
        if extra:
            problems.append(f"{code}: keys not in en.json: {', '.join(extra)}")
        for k in sorted(set(base) & set(m.table)):
            if placeholders(base[k]) != placeholders(m.table[k]):
                problems.append(f"{code}: '{k}' has placeholders {placeholders(m.table[k])}, en.json {placeholders(base[k])}")
    if problems:
        raise MessageError("; ".join(problems))
    return tables


def up(rel):
    """The relative path from the page at rel (POSIX, relative to the version directory) back to that directory."""
    return "../" * rel.count("/")


def shell(m, rel, title, body, langs, base_url, style, nav=""):
    """A page of language m at <prefix><rel> under the version directory. Links to the other languages are relative (the
    site's link check follows them); the hreflang alternates are absolute under base_url, as search engines want them."""
    here = m.prefix + rel
    root = up(here)
    switch = " ".join(
        f'<a hreflang="{o.code}" lang="{o.code}" href="{root}{o.prefix}{rel}"'
        + (' aria-current="page"' if o.code == m.code else "")
        + f">{html.escape(o.name)}</a>"
        for o in langs.values()
    )
    alternates = "".join(
        f'<link rel="alternate" hreflang="{o.code}" href="{html.escape(base_url + o.prefix + rel)}">\n' for o in langs.values()
    )
    alternates += f'<link rel="alternate" hreflang="x-default" href="{html.escape(base_url + rel)}">\n'
    canonical = f'<link rel="canonical" href="{html.escape(base_url + here)}">\n'
    return (
        f'<!DOCTYPE html>\n<html lang="{m.code}">\n<head>\n<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        f"<title>{html.escape(title)}</title>\n{canonical}{alternates}<style>{style}</style>\n</head>\n<body>\n"
        f'<header><a class="name" href="{root}../index.html">Kuicksilver</a>'
        f'<a href="{root}guide/index.html">{html.escape(m("nav.guide"))}</a> '
        f'<a href="{root}api/index.html">{html.escape(m("nav.api"))}</a> '
        f'<a href="{root}{m.prefix}verify/index.html">{html.escape(m("nav.verify"))}</a>'
        f'<nav class="lang" aria-label="{html.escape(m("nav.language"))}">{switch}</nav></header>\n'
        + (f'<div class="layout">{nav}<main>\n{body}\n</main></div>' if nav else f"<main>\n{body}\n</main>")
        + "\n</body>\n</html>\n"
    )
