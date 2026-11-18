"""Cross-checks between the subscriptions, the three copies of the recommended-events
table, and a snapshot of the Windows 11 provider manifests (tests/data/win-snapshot.json)."""

import xml.etree.ElementTree as ET

import pytest

import checks
import efglib as L
import known_issues as K

CHECKS = [
    "table_differences",
    "recommended_unknown_channels",
    "recommended_unknown_providers",
    "recommended_level_mismatches",
    "xpath_problems",
    "subscription_unknown_channels",
    "subscription_unknown_providers",
    "subscription_unknown_event_ids",
    "subscription_level_filter_excludes",
    "subscription_ids_not_recommended",
]


@pytest.mark.parametrize("name", CHECKS)
def test_check_matches_known_issues(name):
    found = getattr(checks, name)()
    known = getattr(K, name.upper())
    new = sorted(found - known)
    fixed = sorted(known - found)
    assert not new, f"new problems found by {name}:\n  " + "\n  ".join(new)
    assert not fixed, f"no longer found by {name}, remove from tests/known_issues.py:\n  " + "\n  ".join(fixed)


@pytest.mark.parametrize("path", L.subscription_files(), ids=lambda p: p.relative_to(L.ROOT).as_posix())
def test_subscription_is_well_formed(path):
    root = L.parse_subscription(path)
    assert root.tag == L.SUB_NS + "Subscription"
    for tag in ("SubscriptionId", "Query", "LogFile"):
        assert root.find(L.SUB_NS + tag) is not None, f"missing <{tag}>"
    ql = ET.fromstring(L.query_list_text(path))
    assert ql.tag == "QueryList"
    queries = ql.findall("Query")
    assert queries, "QueryList has no <Query>"
    assert len({q.get("Id") for q in queries}) == len(queries), "duplicate Query Id"
    assert L.selects(path), "no <Select>"


def test_subscription_ids_unique_per_directory():
    seen = {}
    for path in L.subscription_files():
        sid = L.parse_subscription(path).find(L.SUB_NS + "SubscriptionId").text
        key = (path.parent, sid)
        assert key not in seen, f"{path} and {seen[key]} share SubscriptionId {sid}"
        seen[key] = path


def test_nt6_and_samples_queries_match():
    """samples/ should differ from NT6/ only in comments and whitespace of the query."""
    nt6 = {p.name: p for p in (L.SUBSCRIPTIONS / "NT6").glob("*.xml")}
    samples = {p.name: p for p in (L.SUBSCRIPTIONS / "samples").glob("*.xml")}
    assert nt6.keys() == samples.keys()
    differ = []
    for name in nt6:
        a = [(s.path, s.element, s.xpath) for s in L.selects(nt6[name])]
        b = [(s.path, s.element, s.xpath) for s in L.selects(samples[name])]
        if sorted(a) != sorted(b):
            differ.append(name)
    assert differ == sorted(K.NT6_SAMPLES_DIFFER), differ


def test_checker_catches_known_bug_classes(tmp_path, monkeypatch):
    """The checks must catch the mistakes they claim to: an unbalanced expression,
    a provider name that does not exist (the old DefenderErr.xml), and a level filter
    that excludes the event."""
    src = (L.SUBSCRIPTIONS / "NT6" / "DefenderErr.xml").read_text(encoding="utf-8")
    bad = tmp_path / "Bad.xml"
    monkeypatch.setattr(L, "subscription_files", lambda: [bad])

    bad.write_text(src.replace("(Level=2 or Level=3)", "(Level=2 or Level=3"), encoding="utf-8")
    assert any("does not parse" in p for p in checks.xpath_problems())

    bad.write_text(src.replace("Microsoft-Windows-Windows Defender']", "Windows Defender']"), encoding="utf-8")
    assert checks.subscription_unknown_providers() == {f"{bad.as_posix()}: Windows Defender"}

    bad.write_text(src.replace("(Level=2 or Level=3)", "Level=2"), encoding="utf-8")
    assert f"{bad.as_posix()}: Microsoft-Windows-Windows Defender 1116 is Warning, filter allows ['Error']" in (
        checks.subscription_level_filter_excludes()
    )

    bad.write_text(src.replace(">*[System[", ">//*[System["), encoding="utf-8")
    assert any("'//'" in p for p in checks.xpath_problems())
