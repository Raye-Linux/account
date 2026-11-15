"""Every setting Raye Settings writes is either synced or kept on this PC on
purpose, and common/sync-table.json says which.

Deletes (deleteEntry, revertToDefault) are not listed: they remove a key the
table already decides. A site is a file and a first argument, not a group, so
a key name reused in a file already listed passes; keep that in mind.

The table names write sites the way the code spells them: "<path under
settings/src>:<first argument of writeEntry>" for C++, the same with the
first argument of input.setValue for QML pages. A new writeEntry with a new
key, or a helper called from a new file, is a site the table does not know,
and this test fails until someone decides whether it syncs.

Runs with no build and no network. Without a sibling settings checkout (a
package build) only the checks that need nothing else run, and the others
say so.
"""

import json
import pathlib
import re
import sys
from collections import Counter

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parent
TABLE = json.loads((REPO / "common/sync-table.json").read_text(encoding="utf-8"))
SETTINGS = REPO.parent / "settings"
SRC = SETTINGS / "src"
LONE = not SRC.is_dir()

CALLS = {
    "cpp": re.compile(r"\b(?:writeEntry|writePathEntry|writeXdgListEntry)\("),
    "qml": re.compile(r"\binput\.setValue\("),
}


def first_args(text, call):
    """The first argument of every call, as written, up to its top-level comma."""
    for m in call.finditer(text):
        depth, i, start = 0, m.end(), m.end()
        quote = None
        while i < len(text):
            c = text[i]
            if quote:
                if c == quote and text[i - 1] != "\\":
                    quote = None
            elif c in "\"'":
                quote = c
            elif c in "([{":
                depth += 1
            elif c in ")]}":
                if depth == 0:
                    break
                depth -= 1
            elif c == "," and depth == 0:
                break
            i += 1
        yield " ".join(text[start:i].split())


def lone(name):
    print(f"SKIPPED - {name}: no sibling settings checkout at {SETTINGS}")


def first_arg(raw):
    raw = raw.strip()
    m = re.fullmatch(r"QStringLiteral\((\"[^\"]*\")\)", raw)
    return m.group(1) if m else raw


def scan():
    sites = Counter()
    for ext, call in CALLS.items():
        for path in sorted(SRC.rglob(f"*.{ext}")):
            text = re.sub(r"/\*.*?\*/", "", path.read_text(encoding="utf-8"), flags=re.S)
            text = re.sub(r"(?m)^\s*//[^\n]*|\s//[^\n]*", "", text)
            for arg in first_args(text, call):
                sites[f"{path.relative_to(SRC)}:{first_arg(arg)}"] += 1
    return sites


def triples():
    synced = {f"{e['file']}|{e['group']}|{e['key']}" for e in TABLE["synced"]}
    excluded = {f"{x['file']}|{x['group']}|{x['key']}" for x in TABLE["excluded"]}
    return synced, excluded


def test_every_write_in_settings_is_decided():
    if LONE:
        return lone("test_every_write_in_settings_is_decided")
    found = scan()
    assert found, "found no writeEntry at all in settings/src: the pattern broke"
    unknown = sorted(s for s in found if s not in TABLE["sites"])
    assert not unknown, (
        "Settings writes these and common/sync-table.json does not say whether "
        "they sync: add each to 'sites' with what it writes, then put every "
        "entry in 'synced' or in 'excluded' with a reason: " + "; ".join(unknown))


def test_no_site_in_the_table_is_gone():
    if LONE:
        return lone("test_no_site_in_the_table_is_gone")
    found = scan()
    stale = sorted(s for s in TABLE["sites"] if s not in found)
    assert not stale, "the table names write sites Settings no longer has: " + "; ".join(stale)


def test_every_site_points_at_a_decided_entry():
    synced, excluded = triples()
    for site, writes in TABLE["sites"].items():
        assert writes, f"{site} lists nothing"
        for w in writes:
            assert w in synced or w in excluded, f"{site} writes {w}, neither synced nor excluded"
    assert not synced & excluded, "both synced and excluded: " + ", ".join(sorted(synced & excluded))


def test_every_excluded_entry_says_why():
    for x in TABLE["excluded"]:
        assert len(x.get("why", "")) > 10, f"{x['file']}|{x['group']}|{x['key']}: no reason"


def test_the_watch_unit_watches_every_synced_file():
    unit = (REPO / "client/data/systemd/raye-account-watch.path").read_text(encoding="utf-8")
    watched = set(re.findall(r"^PathChanged=%h/\.config/(\S+)$", unit, re.M))
    missing = sorted({e["file"] for e in TABLE["synced"]} - watched)
    assert not missing, "raye-account-watch.path does not watch: " + ", ".join(missing)


if __name__ == "__main__":
    bad = 0
    for name, case in sorted(globals().items()):
        if not name.startswith("test_"):
            continue
        try:
            case()
        except AssertionError as error:
            bad += 1
            print(f"FAIL - {name}: {error}")
        else:
            print(f"ok - {name}")
    sys.exit(1 if bad else 0)
