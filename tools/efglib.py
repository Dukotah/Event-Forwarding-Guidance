"""Readers for the repository's data files, shared by tests/ and tools/efg_sigma.py.

Three files describe the same "Recommended Events to Collect" table:
Events/RecommendedEvents.json, Events/RecommendedEvents.csv and the tables in
Events/README.md. Subscriptions/**/*.xml hold the WEF subscriptions whose
<Query> CDATA contains an event log QueryList.
"""

from __future__ import annotations

import csv
import json
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EVENTS = ROOT / "Events"
SUBSCRIPTIONS = ROOT / "Subscriptions"
SNAPSHOT = ROOT / "tests" / "data" / "win-snapshot.json"

SUB_NS = "{http://schemas.microsoft.com/2006/03/windows/events/subscription}"


@dataclass(frozen=True, order=True)
class Row:
    category: str
    name: str
    ids: str  # as written, e.g. "865, 866, 867"
    level: str
    eventlog: str
    eventsource: str

    @property
    def id_list(self) -> list[int]:
        return [int(x) for x in re.split(r"\s*,\s*", self.ids.strip())]

    def key(self) -> tuple[str, str, str]:
        return (self.category, self.name, self.ids)


def json_doc() -> dict:
    with open(EVENTS / "RecommendedEvents.json", encoding="utf-8") as fh:
        return json.load(fh)["Recommended Events to Collect"]


def json_entries() -> list[tuple[str, str, str, dict]]:
    """(category, name, ids, raw dict) for every event in the JSON file."""
    out = []
    for cat, body in json_doc().items():
        for name, events in body["events"].items():
            for ids, ev in events.items():
                out.append((cat, name, ids, ev))
    return out


def json_rows() -> list[Row]:
    rows = []
    for cat, name, ids, ev in json_entries():
        rows.append(
            Row(
                cat,
                name,
                ids,
                ev.get("level", ""),
                ev.get("eventlog", ev.get("log", "")),
                ev.get("eventsource", ""),
            )
        )
    return rows


def csv_rows() -> list[Row]:
    rows = []
    with open(EVENTS / "RecommendedEvents.csv", encoding="utf-8", newline="") as fh:
        reader = csv.reader(fh)
        header = [h.strip() for h in next(reader)]
        assert header[:6] == ["Category", "Name", "ID", "Level", "Event Log", "Event Source"], header
        for rec in reader:
            if not any(rec):
                continue
            rows.append(Row(*[c.strip() for c in rec[:6]]))
    return rows


_TABLE_ROW = re.compile(r"^\|(.*)\|\s*$")


def readme_rows() -> list[Row]:
    """Rows from the five-column '| | ID | Level | Event Log | Event Source |' tables."""
    rows = []
    category = None
    in_table = False
    with open(EVENTS / "README.md", encoding="utf-8") as fh:
        for line in fh:
            line = line.rstrip("\r\n")
            if line.startswith("### "):
                category = line[4:].strip()
                in_table = False
                continue
            m = _TABLE_ROW.match(line)
            if not m:
                in_table = False
                continue
            cells = [c.strip() for c in m.group(1).split("|")]
            if cells[1:] == ["ID", "Level", "Event Log", "Event Source"]:
                in_table = True
                continue
            if not in_table or set("".join(cells)) <= set("- "):
                continue
            if len(cells) == 5:
                rows.append(Row(category, *cells))
    return rows


@dataclass(frozen=True)
class Select:
    file: Path
    query_id: str
    query_path: str
    element: str  # "Select" or "Suppress"
    path: str
    xpath: str

    @property
    def providers(self) -> list[str]:
        return re.findall(r"Provider\[@Name='([^']+)'\]", self.xpath)

    @property
    def event_ids(self) -> list[int]:
        ids = [int(x) for x in re.findall(r"EventID\s*=\s*(\d+)", self.xpath)]
        for lo, hi in re.findall(r"EventID\s*>=\s*(\d+)\s+and\s+EventID\s*<=\s*(\d+)", self.xpath):
            ids.extend(range(int(lo), int(hi) + 1))
        return ids

    @property
    def levels(self) -> list[int]:
        return [int(x) for x in re.findall(r"Level\s*=\s*(\d+)", self.xpath)]


def subscription_files() -> list[Path]:
    return sorted(SUBSCRIPTIONS.rglob("*.xml"))


def parse_subscription(path: Path) -> ET.Element:
    return ET.parse(path).getroot()


def query_list_text(path: Path) -> str:
    root = parse_subscription(path)
    q = root.find(SUB_NS + "Query")
    if q is None or q.text is None:
        raise ValueError(f"{path}: no <Query> CDATA")
    return q.text.strip()


def selects(path: Path) -> list[Select]:
    ql = ET.fromstring(query_list_text(path))
    if ql.tag != "QueryList":
        raise ValueError(f"{path}: CDATA root is <{ql.tag}>, expected <QueryList>")
    out = []
    for query in ql.findall("Query"):
        for el in query:
            if not isinstance(el.tag, str):
                continue
            out.append(
                Select(
                    path,
                    query.get("Id", ""),
                    query.get("Path", ""),
                    el.tag,
                    el.get("Path", ""),
                    (el.text or "").strip(),
                )
            )
    return out


@lru_cache(maxsize=1)
def snapshot() -> dict:
    with open(SNAPSHOT, encoding="utf-8-sig") as fh:
        return json.load(fh)


LEVEL_NAMES = {0: "LogAlways", 1: "Critical", 2: "Error", 3: "Warning", 4: "Information", 5: "Verbose"}
