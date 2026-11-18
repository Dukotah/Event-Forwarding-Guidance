"""Each function returns the set of problems it finds, as short strings.

The tests compare these sets with tests/known_issues.py, so a new problem fails the
build and so does fixing a known one without removing it from the list.
"""

from __future__ import annotations

import re

import efglib as L
from elementpath import XPath1Parser

# Functions the Windows event log XPath 1.0 subset accepts.
ALLOWED_FUNCTIONS = {"band", "timediff", "position"}

# Providers whose events are defined in a message table rather than the manifest,
# so Get-WinEvent -ListProvider does not list every ID they write.
LEGACY_PROVIDERS = {
    "service control manager",
    "microsoft-windows-application-experience",
    "msiinstaller",
    "application error",
    "application hang",
    "windows error reporting",
    "user32",
}


def _snapshot_maps():
    snap = L.snapshot()
    channels = {c.lower() for c in snap["channels"]}
    providers = {k.lower(): v for k, v in snap["providers"].items()}
    return channels, providers


def _rel(path) -> str:
    try:
        return path.relative_to(L.ROOT).as_posix()
    except ValueError:
        return path.as_posix()


def table_differences() -> set[str]:
    """Rows present in one of JSON/CSV/README but not another."""
    j, c, m = set(L.json_rows()), set(L.csv_rows()), set(L.readme_rows())
    out = set()
    for a, b, label in ((j, c, "json-not-csv"), (c, j, "csv-not-json"), (j, m, "json-not-readme"), (m, j, "readme-not-json")):
        for r in a - b:
            out.add(f"{label}: {r.category} | {r.name} | {r.ids} | {r.level} | {r.eventlog} | {r.eventsource}")
    return out


def recommended_unknown_channels() -> set[str]:
    channels, _ = _snapshot_maps()
    return {f"{r.category} | {r.name}: {r.eventlog}" for r in L.json_rows() if r.eventlog.lower() not in channels}


def recommended_unknown_providers() -> set[str]:
    _, providers = _snapshot_maps()
    return {r.eventsource for r in L.json_rows() if r.eventsource and r.eventsource.lower() not in providers}


def recommended_level_mismatches() -> set[str]:
    """Documented level differs from the level the provider manifest declares."""
    _, providers = _snapshot_maps()
    out = set()
    for r in L.json_rows():
        p = providers.get(r.eventsource.lower())
        if not p or r.eventsource.lower() in LEGACY_PROVIDERS:
            continue
        for i in r.id_list:
            lvl = p["events"].get(str(i))
            if lvl is None:
                if p["events"]:
                    out.add(f"{r.category} | {r.name}: {r.eventsource} {i} not in manifest")
                continue
            documented = [x.strip() for x in r.level.split(",")]
            if lvl not in documented:
                out.add(f"{r.category} | {r.name}: {i} documented {r.level}, manifest {lvl}")
    return out


def all_selects():
    for f in L.subscription_files():
        for s in L.selects(f):
            yield s


def xpath_problems() -> set[str]:
    out = set()
    parser = XPath1Parser()
    for s in all_selects():
        where = f"{_rel(s.file)} {s.element}[{s.path}]"
        if not s.path:
            out.add(f"{where}: missing Path")
        if not s.xpath:
            out.add(f"{where}: empty expression")
            continue
        try:
            parser.parse(s.xpath)
        except Exception as exc:  # elementpath raises several error classes
            out.add(f"{where}: does not parse: {exc}")
            continue
        if "//" in s.xpath:
            out.add(f"{where}: '//' is not supported by the event log XPath subset")
        for fn in re.findall(r"([A-Za-z_-]+)\s*\(", s.xpath):
            if fn not in ALLOWED_FUNCTIONS and fn not in ("and", "or"):
                out.add(f"{where}: function {fn}() is not supported")
    return out


def subscription_unknown_channels() -> set[str]:
    channels, _ = _snapshot_maps()
    return {f"{_rel(s.file)}: {s.path}" for s in all_selects() if s.path.lower() not in channels}


def subscription_unknown_providers() -> set[str]:
    _, providers = _snapshot_maps()
    out = set()
    for s in all_selects():
        for p in s.providers:
            if p.lower() not in providers:
                out.add(f"{_rel(s.file)}: {p}")
    return out


def subscription_unknown_event_ids() -> set[str]:
    _, providers = _snapshot_maps()
    out = set()
    for s in all_selects():
        for p in s.providers:
            meta = providers.get(p.lower())
            if not meta or not meta["events"] or p.lower() in LEGACY_PROVIDERS:
                continue
            for i in s.event_ids:
                if str(i) not in meta["events"]:
                    out.add(f"{_rel(s.file)}: {p} {i}")
    return out


def subscription_level_filter_excludes() -> set[str]:
    """A Select filters on Level but the manifest says the event is written at another level,
    so the event can never be forwarded."""
    _, providers = _snapshot_maps()
    out = set()
    for s in all_selects():
        if s.element != "Select" or not s.levels:
            continue
        allowed = {L.LEVEL_NAMES[x] for x in s.levels}
        for p in s.providers:
            meta = providers.get(p.lower())
            if not meta:
                continue
            for i in s.event_ids:
                lvl = meta["events"].get(str(i))
                if lvl and lvl not in allowed:
                    out.add(f"{_rel(s.file)}: {p} {i} is {lvl}, filter allows {sorted(allowed)}")
    return out


def subscription_ids_not_recommended() -> set[str]:
    """(provider, event ID) pairs a subscription forwards that RecommendedEvents.json does not list."""
    rec = set()
    for r in L.json_rows():
        for i in r.id_list:
            rec.add((r.eventsource.lower(), i))
    out = set()
    for s in all_selects():
        if s.element != "Select" or "modern" in s.file.parts:
            continue
        for p in s.providers:
            for i in s.event_ids:
                if (p.lower(), i) not in rec:
                    out.add(f"{_rel(s.file)}: {p} {i}")
    return out
