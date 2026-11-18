"""Generate Sigma rules from Events/RecommendedEvents.json.

One rule per (category, name, event log). Rules are collection/hunting rules at
level "informational": they describe what the guidance says to collect, they are not
tuned detections. Output is deterministic so CI can check it is up to date.

    python tools/efg_sigma.py            # write sigma/
    python tools/efg_sigma.py --check    # exit 1 if sigma/ is stale
"""

from __future__ import annotations

import argparse
import re
import sys
import uuid
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
import efglib as L  # noqa: E402

OUT = L.ROOT / "sigma"
RULE_DATE = "2026-11-17"
NAMESPACE = uuid.UUID("5f0c8a52-4c55-4f1e-9b8e-2d0f6a1e0e19")
REPO = "https://github.com/nsacyber/Event-Forwarding-Guidance"

# Event log -> Sigma windows "service", following the SigmaHQ logsource taxonomy.
# Logs without an entry are matched with a Channel condition instead.
SERVICES = {
    "security": "security",
    "system": "system",
    "application": "application",
    "setup": "setup",
    "microsoft-windows-powershell/operational": "powershell",
    "powershell": "powershell-classic",
    "windows powershell": "powershell-classic",
    "microsoft-windows-applocker/exe and dll": "applocker",
    "microsoft-windows-applocker/msi and script": "applocker",
    "microsoft-windows-applocker/packaged app-deployment": "applocker",
    "microsoft-windows-applocker/packaged app-execution": "applocker",
    "microsoft-windows-codeintegrity/operational": "codeintegrity-operational",
    "microsoft-windows-windows defender/operational": "windefend",
    "microsoft-windows-windows firewall with advanced security/firewall": "firewall-as",
    "microsoft-windows-taskscheduler/operational": "taskscheduler",
    "microsoft-windows-printservice/operational": "printservice-operational",
    "microsoft-windows-capi2/operational": "capi2",
    "microsoft-windows-dns-client/operational": "dns-client",
    "microsoft-windows-lsa/operational": "lsa-server",
}

# Fixes for values in RecommendedEvents.json that are not real channel names
# (see tests/known_issues.py RECOMMENDED_UNKNOWN_CHANNELS).
CHANNEL_FIXES = {
    "User32": "System",
    "Powershell": "Windows PowerShell",
    "Microsoft-Windows-Kernel-PnP/Device Configuration": "Microsoft-Windows-Kernel-PnP/Configuration",
}

# 7045 is written by Service Control Manager, not FilterManager (upstream issue #13).
PROVIDER_FIXES = {("7045", "Microsoft-Windows-FilterManager"): "Service Control Manager"}


def slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")


def build_rules() -> list[tuple[str, dict]]:
    doc = L.json_doc()
    groups: dict[tuple[str, str, str, str], dict] = {}
    for cat, name, ids, ev in L.json_entries():
        log = ev.get("eventlog", ev.get("log", ""))
        log = CHANNEL_FIXES.get(log, log)
        provider = ev.get("eventsource", "")
        provider = PROVIDER_FIXES.get((ids, provider), provider)
        extra = tuple(
            (field, ev[key])
            for key, field in (("logontype", "LogonType"), ("authenticationpkg", "AuthenticationPackageName"))
            if ev.get(key) and ev[key] != "N/A"
        )
        key = (cat, name, log, provider, extra)
        g = groups.setdefault(key, {"ids": [], "notes": []})
        g["ids"].extend(int(x) for x in re.split(r"\s*,\s*", ids))
        for n in (ev.get("notes"), ev.get("footnote")):
            if n and n not in g["notes"]:
                g["notes"].append(n)

    rules = []
    for (cat, name, log, provider, extra), g in sorted(groups.items()):
        ids = sorted(set(g["ids"]))
        service = SERVICES.get(log.lower())
        logsource = {"product": "windows"}
        selection: dict = {}
        if service:
            logsource["service"] = service
        else:
            selection["Channel"] = log
        if provider:
            selection["Provider_Name"] = provider
        selection["EventID"] = ids if len(ids) > 1 else ids[0]
        for field, value in extra:
            selection[field] = int(value) if value.isdigit() else value

        title = f"NSA Event Forwarding Guidance - {cat}: {name}"
        rid = str(uuid.uuid5(NAMESPACE, f"{cat}|{name}|{log}|{provider}|{extra}"))
        desc = doc[cat].get("description", "")
        if isinstance(desc, list):
            desc = " ".join(desc)
        desc = desc.strip()
        description = f"Recommended event to collect: {name} ({log}, event ID {', '.join(map(str, ids))})."
        if g["notes"]:
            description += " " + " ".join(n.rstrip(".") + "." for n in g["notes"])
        if desc:
            description += f" Category guidance: {desc}"
        rule = {
            "title": title,
            "id": rid,
            "status": "experimental",
            "description": description,
            "references": [f"{REPO}/blob/master/Events/README.md"],
            "author": "Generated from nsacyber/Event-Forwarding-Guidance Events/RecommendedEvents.json",
            "date": RULE_DATE,
            "tags": ["detection.threat-hunting"],
            "logsource": logsource,
            "detection": {"selection": selection, "condition": "selection"},
            "falsepositives": ["Expected in normal operation; this rule marks events to collect, not malicious activity"],
            "level": "informational",
        }
        base = f"{slug(cat)}/win_efg_{slug(name)}"
        idtext = "_".join(map(str, ids))
        pieces = [(slug(log.split("/")[-1]), log.split("/")[-1]), (idtext, f"event {', '.join(map(str, ids))}")]
        rules.append({"base": base, "pieces": pieces, "used": [], "rule": rule})
    # Add suffixes only where needed to keep file names and titles unique.
    def fname(r):
        return "_".join([r["base"]] + [s for s, _ in r["used"]])

    for depth in range(1, 8):
        names = [fname(r) for r in rules]
        dupes = {n for n in names if names.count(n) > 1}
        if not dupes:
            break
        for r, n in zip(rules, names):
            if n in dupes and r["pieces"]:
                r["used"].append(r["pieces"].pop(0))
    names = [fname(r) for r in rules]
    assert len(names) == len(set(names)), "duplicate rule file names"
    for r in rules:
        if r["used"]:
            r["rule"]["title"] += " (" + ", ".join(label for _, label in r["used"]) + ")"
    rules = [(n + ".yml", r["rule"]) for n, r in zip(names, rules)]
    return rules


def render(rule: dict) -> str:
    return yaml.safe_dump(rule, sort_keys=False, allow_unicode=False, width=1000)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--check", action="store_true", help="fail if sigma/ does not match the generator output")
    args = ap.parse_args()
    wanted = {OUT / f: render(r) for f, r in build_rules()}
    existing = set(OUT.rglob("*.yml")) if OUT.exists() else set()
    if args.check:
        stale = [p for p, text in wanted.items() if not p.exists() or p.read_text(encoding="utf-8") != text]
        extra = existing - set(wanted)
        for p in stale + sorted(extra):
            print(f"stale: {p.relative_to(L.ROOT)}")
        return 1 if stale or extra else 0
    for p in existing - set(wanted):
        p.unlink()
    for p, text in wanted.items():
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
    print(f"wrote {len(wanted)} rules to {OUT.relative_to(L.ROOT)}/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
