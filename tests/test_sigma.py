"""The generated Sigma rules must be current and must parse with pySigma."""

import efg_sigma
import pytest
from sigma.collection import SigmaCollection


def test_sigma_rules_are_up_to_date():
    assert efg_sigma.OUT.exists()
    wanted = {efg_sigma.OUT / f: efg_sigma.render(r) for f, r in efg_sigma.build_rules()}
    on_disk = set(efg_sigma.OUT.rglob("*.yml"))
    assert on_disk == set(wanted), "run: python tools/efg_sigma.py"
    stale = [p.name for p, text in wanted.items() if p.read_text(encoding="utf-8") != text]
    assert not stale, f"stale rules, run: python tools/efg_sigma.py: {stale}"


def test_sigma_rules_parse():
    rules = sorted(efg_sigma.OUT.rglob("*.yml"))
    collection = SigmaCollection.load_ruleset([str(p) for p in rules], collect_errors=True)
    errors = [(r.source, r.errors) for r in collection.rules if r.errors]
    assert not errors
    assert len(collection.rules) == len(rules)


@pytest.mark.parametrize("ids", [8004, 8007])
def test_applocker_block_rules_use_error_events(ids):
    """Regression for upstream issue #19: blocked AppLocker events are 8004/8007."""
    found = [r for _, r in efg_sigma.build_rules() if r["detection"]["selection"].get("EventID") == ids]
    assert found and all("AppLocker Block" in r["title"] for r in found)
