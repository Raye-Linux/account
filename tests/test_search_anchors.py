# SPDX-License-Identifier: GPL-3.0-or-later
"""The Settings pages this repository owns, and the search rows they owe.

client/settings/pages/ holds Settings pages written here and merged into
the settings repository. Each row of such a page names itself with
searchId, and Raye Settings can only find a row by name if
settings/data/search/*.json carries a row with the same id. The pairing
is checked over there by tests/test_search_index.cpp (anchorsMeet), which
LISTS what does not meet instead of failing: ST-27 is the ticket that
turns it strict.

Two things that check cannot do, and this one does:

  * it needs Qt6 to build. Measured 2026-11-06 on Debian 13 in this tree:
    cmake stops on "Failed to find required Qt component Multimedia", so
    on a machine like this one NOTHING checks these anchors at all.
  * it prints a list, it does not count one. A list nobody counts drifts:
    a relevé of this very set said 16 one day and 12 another. So the
    figure is written down here, once, and a change to it has to be
    deliberate.

    python3 -I -B tests/test_search_anchors.py

The settings repository is read, never written. Cloned on its own, with
no sibling settings checkout, the checks that need it say so on the line
rather than passing quietly.
"""
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
RAYE = ROOT.parent
SETTINGS = RAYE / "settings"
# Where this repository keeps the pages, and where settings ships them.
OURS = ROOT / "client/settings/pages"
THEIRS = SETTINGS / "src/qml/pages"
LONE = not SETTINGS.is_dir()

# The same expression tests/test_search_index.cpp uses, so the two can
# never read the same file and disagree.
SEARCH_ID = re.compile(r'\bsearchId\s*:\s*"([^"]+)"')

# How many anchors of OUR pages have no row in settings/data/search yet.
# It is a completeness figure, not a breakage: it goes to 0 the day the
# rows land, and every one of them is a row somebody has to write (a
# label and its keywords, in both languages -- content, not a path).
# Measured 2026-11-06: 11.
#
# One of the 11 is not a row anyone can write: RayeBackupPage.qml says
#    searchId: "sync-" + modelData.id
# inside a Repeater, and the expression above -- in C++ as here -- reads
# the literal and comes away with "sync-". The four real anchors are
# sync-personalization, sync-taskbar, sync-language and sync-accessibility.
# Before ST-27 turns the pairing strict, that expression has to learn to
# leave a concatenated searchId alone, or it will demand a row called
# "sync-" for ever.
OWED_ANCHORS = 11


def lone(name):
    """Say so, without printing a second verdict.

    ⚠️ The line is read by eye and by the launcher: a note starting with
    "ok" or "FAIL" would be counted on top of the verdict below it.
    """
    print(f"-- {name}: no sibling settings checkout, nothing to compare")


def our_pages():
    """Every QML file of client/settings/pages, relative to that folder."""
    files = sorted(p.relative_to(OURS) for p in OURS.rglob("*.qml"))
    assert files, (f"{OURS} holds no .qml at all: either the "
                   f"pages moved or this check stopped looking where they are "
                   f"-- an empty sweep must not pass as green")
    return files


def layout():
    """(page id, component) for every page settings declares."""
    text = (SETTINGS / "data/layout.json").read_text(encoding="utf-8")
    pages = [(p.get("id"), p.get("component") or "")
             for category in json.loads(text).get("categories", [])
             for p in category.get("pages", [])]
    assert pages, "settings/data/layout.json declares no page"
    return pages


def page_of(pages, relative):
    """The page a QML file draws, as test_search_index.cpp decides it:
    the page whose component it is, else the page of the same folder
    whose component name it starts with. Empty when there is none."""
    relative = f"pages/{relative}"
    folder = str(pathlib.PurePosixPath(relative).parent)
    base = pathlib.PurePosixPath(relative).stem
    best, best_len = "", 0
    for page_id, component in pages:
        if component == relative:
            return page_id
        if not component or str(pathlib.PurePosixPath(component).parent) != folder:
            continue
        stem = pathlib.PurePosixPath(component).stem
        stem = stem[:-4] if stem.endswith("Page") else stem
        if stem and base.startswith(stem) and len(stem) > best_len:
            best, best_len = page_id, len(stem)
    return best


def search_rows():
    """(id, anchor) of every row of settings/data/search, synonyms apart.

    Both shapes the index loader accepts are read: a bare array, and an
    object with "entries". Reading only one would silently drop five
    files -- display, home, privacy, recovery and sound are arrays today.
    """
    folder = SETTINGS / "data/search"
    rows = []
    for path in sorted(folder.glob("*.json")):
        if path.name == "synonyms.json":
            continue
        doc = json.loads(path.read_text(encoding="utf-8"))
        entries = doc if isinstance(doc, list) else doc.get("entries", [])
        for entry in entries:
            row_id = entry.get("id", "")
            rows.append((row_id, row_id.partition("#")[2]))
    assert rows, f"{folder} holds no search row at all"
    return rows


def test_settings_ships_our_pages_unchanged():
    """Two copies of a page is the oldest trap in this tree: you edit the
    one that is not loaded and nothing changes. These files are written
    here and shipped from settings/src/qml, so they have to be equal byte
    for byte -- and the day they are not, the one that reaches a person
    is settings'."""
    if LONE:
        return lone("test_settings_ships_our_pages_unchanged")
    bad = []
    for relative in our_pages():
        theirs = THEIRS / relative
        if not theirs.is_file():
            bad.append(f"{relative}: settings does not ship it")
        elif theirs.read_bytes() != (OURS / relative).read_bytes():
            bad.append(f"{relative}: differs from settings/src/qml/pages/{relative}")
    assert not bad, ("the copy a person actually runs is settings', so these have "
                     "drifted out of this repository's hands: " + "; ".join(bad))


def test_our_anchors_owe_exactly_what_this_file_says():
    """Every searchId of our pages, against settings/data/search.

    The list is derived at run time from both sides. Writing down which
    anchors are missing would be a list that goes stale in exactly the
    way this check exists to catch.
    """
    if LONE:
        return lone("test_our_anchors_owe_exactly_what_this_file_says")
    pages = layout()
    ids = {row_id for row_id, _ in search_rows()}
    anchors = {anchor for _, anchor in search_rows() if anchor}
    seen, owed = 0, []
    for relative in our_pages():
        text = (OURS / relative).read_text(encoding="utf-8")
        for search_id in SEARCH_ID.findall(text):
            seen += 1
            page = page_of(pages, str(relative).replace("\\", "/"))
            if not page:
                # a file of no page: its row may sit under any page, but
                # it has to be somewhere
                if search_id not in anchors:
                    owed.append(f"{relative}: {search_id} (file of no page)")
                continue
            if f"{page}#{search_id}" not in ids:
                owed.append(f"{relative}: {page}#{search_id}")
    assert seen, ("not one searchId was found in our pages: the rows stopped "
                  "naming themselves, or this check reads the wrong files")
    if len(owed) != OWED_ANCHORS:
        way = "lower" if len(owed) < OWED_ANCHORS else "raise"
        raise AssertionError(
            f"our pages owe {len(owed)} search rows, OWED_ANCHORS says "
            f"{OWED_ANCHORS}: {way} it in this file and say why -- " + "; ".join(owed))


def test_the_pairing_is_checked_strictly_somewhere():
    """ST-27 flips settings' own check to strict. On the day it does, the
    figure above has to be 0, and this file can go. Until then the flag
    must still be there to flip: a check whose switch was deleted is a
    check that will never become strict, and nothing else would say so.
    """
    if LONE:
        return lone("test_the_pairing_is_checked_strictly_somewhere")
    control = SETTINGS / "tests/test_search_index.cpp"
    assert control.is_file(), (
        f"{control} is gone: the strict pairing this file counts towards was "
        f"checked there. Find where it moved rather than dropping the count")
    text = control.read_text(encoding="utf-8")
    assert re.search(r"\bstrictAnchors\s*=\s*(true|false)\b", text), (
        "settings/tests/test_search_index.cpp no longer has a strictAnchors "
        "switch: either ST-27 landed (then OWED_ANCHORS must be 0 and this file "
        "can go) or the switch was lost")


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
        except Exception as error:
            bad += 1
            print(f"FAIL - {name}: {type(error).__name__}: {error}")
        else:
            print(f"ok - {name}")
    sys.exit(1 if bad else 0)
