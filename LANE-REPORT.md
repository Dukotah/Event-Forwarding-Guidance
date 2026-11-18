# LANE 4 report: Event-Forwarding-Guidance

## 1. Upstream contribution rules (CONTRIBUTING.md)

- Contributions are released under CC0 1.0. A non-government contributor waives copyright by opening the PR.
- There is no CLA, no DCO sign-off, no PR template and no test or CI convention.
- The repo has been dormant since 2019-04-12. Only 4 PRs have ever been merged, all from outsiders. Open PRs #12, #16 and #18 have had no reply.

## 2. Branches

| Branch | Base | Bound for | Commit |
|---|---|---|---|
| `fix/19-applocker-levels-defender-provider` | upstream/master | upstream PR (#19 + Defender) | `b6c1be6` Fix AppLocker event levels and DefenderErr provider name |
| `lane/modern-wef` | the fix branch | fork only | `3b5a3fd` Add consistency tests, modern subscriptions and Sigma generator, plus this report |

### A: `fix/19-applocker-levels-defender-provider` (5 files, +28/-26)

- **#19.** In `Events/RecommendedEvents.json`, `.csv` and `Events/README.md`, 8003/8004 and 8006/8007 had their levels swapped, and 8002 ("was allowed to run") was listed under "AppLocker Block". The fix:
  - "AppLocker Block" now holds 8004 and 8007 (Error).
  - "AppLocker Warning" now holds 8003 and 8006 (Warning, audit only).
  - 8002 has its own row, "Executable or DLL ran", modelled on the existing "Script or Installer ran" (8005).
  - The JSON `notes` say which enforcement mode produces each event.
  - Row order follows the repo's existing alphabetical order.
- **DefenderErr.xml** (NT6 and samples). The query filtered `Provider[@Name='Windows Defender']`. The provider that writes `Microsoft-Windows-Windows Defender/Operational` is `Microsoft-Windows-Windows Defender`, which is the name the repo's own README uses, so the subscription forwarded nothing. Changed to the real name.
- **1116 and 1119 added; 1117 and 1118 not added.** The README recommends 1116-1119. 1116 (Warning) and 1119 (Error) fit the subscription's existing `Level=2 or Level=3` filter, so I added them. 1117 and 1118 are Information in the manifest, so adding them would change what an "Errors" subscription means. 1007 and 1009 are already left out for the same reason.

Sources:
- Microsoft Learn, "Using Event Viewer with AppLocker" (ms.date 2024-09-11): https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/using-event-viewer-with-applocker . It lists 8002 Information "allowed to run", 8003 Warning "would have been prevented ... if enforced", 8004 Error "was prevented from running", and the same pattern for 8005/8006/8007.
- Microsoft Learn, "Microsoft Defender Antivirus event IDs and error codes": https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-microsoft-defender-antivirus . It names the log `Microsoft-Windows-Windows Defender/Operational`.
- The local provider manifests on Windows 11 Home 10.0.26200, shown below.

### B: `lane/modern-wef` (fork only)

- **`tests/` (pytest, 60 tests).**
  - Cross-checks the JSON, CSV and README tables against each other.
  - Parses every `<Select>` and `<Suppress>` XPath with `elementpath`'s XPath 1.0 parser. It also rejects `//` and any function other than `band`/`timediff`/`position`, which the event log's XPath subset does not accept.
  - Compares every channel, provider, event ID and `Level=` filter against `tests/data/win-snapshot.json`. That snapshot of the Windows 11 manifests comes from `tools/Export-WinEventSnapshot.ps1` (read-only).
  - Checks that `NT6/` and `samples/` query the same thing.
  - Includes a self-test proving the checks catch an unbalanced expression, the old Defender provider name, and a level filter that excludes the event.
  - The problems that already exist upstream are listed in `tests/known_issues.py` with reasons. The suite fails on any new problem, and also when a listed one is fixed but not removed from the list.
- **`tools/Test-SubscriptionQueries.ps1`.** Runs every QueryList through `Get-WinEvent -FilterXml` and reports MATCH, NOEVENTS, NOCHANNEL, DENIED or INVALID. It exits 1 on INVALID. `-RequireMatch` turns "valid but no events" into a failure for the files you name.
- **`Subscriptions/modern/`.** Four subscriptions in the repo's existing format:
  - `DefenderDetections.xml`: 1116-1119, 5001, 5007, 5013.
  - `ExploitProtection.xml`: Security-Mitigations KernelMode and UserMode, events 1-36. It replaces EMET, which reached end of life in 2018.
  - `CodeIntegrityPolicy.xml`: App Control (WDAC) 3033, 3034, 3076, 3077.
  - `PowerShellScriptBlock.xml`: 4104 with no level filter, because the manifest level is Verbose and suspicious blocks are raised to Warning.
- **`tools/efg_sigma.py` and `sigma/`.** 168 deterministic Sigma rules generated from `RecommendedEvents.json`, one per (category, name, log).
  - Each log maps to a SigmaHQ `service` where one exists. Otherwise the rule matches on `Channel`.
  - The generator corrects the channel names it knows are wrong (`Powershell` becomes `Windows PowerShell`, `User32` becomes `System`, `Kernel-PnP/Device Configuration` becomes `Kernel-PnP/Configuration`), and the 7045 provider (#13).
  - The rules are `informational` collection rules, not tuned detections.
- **`.github/workflows/checks.yml`.**
  - An ubuntu job runs pytest, `efg_sigma.py --check`, `sigma check --fail-on-issues` and `sigma convert -t splunk` (asserting 168 queries come out).
  - A windows-latest job runs `Test-SubscriptionQueries.ps1`. The runner is elevated, so the Security-log queries are validated there. It also uploads a snapshot of the runner's manifests.

**Other upstream bugs found by the suite.** None are fixed upstream yet; all are recorded in `known_issues.py`:
- `WinUpdateErr.xml` selects `Level=2`, but the WindowsUpdateClient manifest writes 34 and 35 at Warning, so those two IDs are never forwarded.
- `samples/ServiceManager.xml` selects 7045 with `Level=1` (Critical). Locally `Level=1` returns 0 events and `Level=4` returns 117, so the sample never forwards new-service events.
- The JSON uses channel names that do not exist: `Powershell`, `User32`, `Microsoft-Windows-Kernel-PnP/Device Configuration`.
- The JSON/README category names drift: "Network Policy" vs "Network Host Activities", and "Windows Defender Activities" vs "Windows Defender Antivirus Activities".
- The CSV is missing the PtH and RDP rows, has CA 90 where the JSON has 95, and collapses 4104-4106 into one row.
- Documented levels disagree with the manifest for Defender 2004, WLAN 11010 and PowerShell 4104-4106.

## 3. Evidence

These checks ran on the host (Windows 11 Home 10.0.26200, pwsh 7, not elevated) and in WSL (uv venv, Python 3.12.13).

Provider manifests:
```
PS> (Get-WinEvent -ListProvider Microsoft-Windows-AppLocker).Events | ? Id -in 8002..8007
8002 Information | %11 was allowed to run.
8003 Warning     | %11 was allowed to run but would have been prevented from running if the AppLocker policy ...
8004 Error       | %11 was prevented from running.
8005 Information | %11 was allowed to run.
8006 Warning     | %11 was allowed to run but would have been prevented from running if the AppLocker policy ...
8007 Error       | %11 was prevented from running.
PS> Get-WinEvent -ListProvider *Defender*
Microsoft-Windows-Windows Defender :: Microsoft-Windows-Windows Defender/Operational,Microsoft-Windows-Windows Defender/WHC
PS> # Defender manifest levels: 1116 Warning, 1117 Information, 1118 Information, 1119 Error
```

DefenderErr.xml, before (upstream/master) and after (branch A), using the QueryList from the CDATA with `Get-WinEvent -FilterXml`:
```
before  NT6/DefenderErr.xml      OK   matches=0
before  samples/DefenderErr.xml  OK   matches=0
after   NT6/DefenderErr.xml      OK   matches=14
after   samples/DefenderErr.xml  OK   matches=14
after, grouped:  2 x 1116 Warning, 1 x 2001 Error, 1 x 2004 Error, 8 x 3002 Error, 2 x 5008 Error
```
The same log already held 3002, 5008, 2001 and 2004 events written by `Microsoft-Windows-Windows Defender`, so the old query had real events to match and returned none.

All 45 subscriptions with `tools/Test-SubscriptionQueries.ps1 -RequireMatch <DefenderErr + 4 modern>`:
```
MATCH    Subscriptions/modern/CodeIntegrityPolicy.xml      (local: 305 x 3033, 71 x 3077)
MATCH    Subscriptions/modern/DefenderDetections.xml       (1001 x 5007, 2 x 1116, 2 x 1117, 1 x 5001)
MATCH    Subscriptions/modern/ExploitProtection.xml        (374 KernelMode events, IDs 1,3,10,12,31,36)
MATCH    Subscriptions/modern/PowerShellScriptBlock.xml    (457 x 4104)
MATCH    Subscriptions/NT6/DefenderErr.xml
...
DENIED    12   (Security-log queries; the shell is not elevated -> validated by the windows-latest CI job)
MATCH     17
NOEVENTS  14
exit=0
```
INVALID is real. A bogus channel gives "There is not an event log on the localhost computer that matches ...". An unbalanced XPath gives "The specified query is invalid."

pytest and Sigma (WSL):
```
$ python -m pytest -q tests
60 passed in 62.73s
$ sigma check -c tools/sigma-validation.yml --fail-on-issues sigma
Found 0 errors, 0 condition errors and 0 issues.     (exit 0)
$ sigma convert -t splunk -p splunk_windows sigma -o efg.spl ; grep -c . efg.spl
168
(source IN ("WinEventLog:Microsoft-Windows-AppLocker/MSI and Script", ...)) Provider_Name="Microsoft-Windows-AppLocker" EventCode=8004
```
`tools/sigma-validation.yml` waives exactly one rule (Process Created 4688) from SigmaHQ's "use process_creation instead" style check. The guidance recommends the Security event itself.

The suite catches the bugs on unmodified upstream/master (tests copied onto `git archive upstream/master`):
```
new problems found by recommended_level_mismatches:
    Application Whitelisting | AppLocker Block: 8003 documented Error, manifest Warning
    Application Whitelisting | AppLocker Block: 8004 documented Warning, manifest Error
    Application Whitelisting | AppLocker Warning: 8006 documented Error, manifest Warning
    Application Whitelisting | AppLocker Warning: 8007 documented Warning, manifest Error
new problems found by subscription_unknown_providers:
    Subscriptions/NT6/DefenderErr.xml: Windows Defender
    Subscriptions/samples/DefenderErr.xml: Windows Defender
```
It also catches #13 (7045 attributed to FilterManager) and #14 (the README cert provider name), which are listed in `known_issues.py`.

GitHub Actions on the fork (run 44243941800, workflow_dispatch on `lane/modern-wef`): **green**.
https://github.com/Dukotah/Event-Forwarding-Guidance/actions/runs/44243941800
```
data consistency + Sigma        ok   60 passed; sigma check: 0 errors, 0 issues; 168 SPL queries
Get-WinEvent -FilterXml (windows-latest, elevated)  ok
    MATCH 17, NOEVENTS 26, DENIED 0, NOCHANNEL 0, INVALID 0   -> all 45 queries, Security log included, accepted
```

**What I could not verify.** Real WEC delivery: there is no collector or domain here, and I created no subscriptions (no wecutil, no `wevtutil set`). I triggered no AppLocker 8003/8004 events, because doing so would mean changing the host's AppLocker policy. The AppLocker levels rest on the manifest and Microsoft Learn.

## 4. Competing work check

- `gh pr list -R nsacyber/Event-Forwarding-Guidance --state all -L 50`, run at start and end, shows PRs #2, #4, #5, #6, #7, #11, #12, #16, #18, #20 and #21. None of them touches AppLocker or DefenderErr.
  - #7 (merged 2017) fixed a different spelling issue in the DefenderErr query.
  - #12 covers #13, and #16 covers #14. I did not duplicate either.
- Issue #19 has no PR and no comments. The Defender provider bug has no issue: searching issues for "defender" returns only #19.
- No spray accounts appear (theyottaboy, rudycelekli, arpitjain099, arthurianresolve, ravisastryk, r3vpwnx).

## 5. Draft upstream text

### Issue (Defender provider), to file before or with the PR

**Title:** DefenderErr.xml filters on provider 'Windows Defender' and matches nothing on Windows 10/11

```
Subscriptions/NT6/DefenderErr.xml and Subscriptions/samples/DefenderErr.xml select

    *[System[Provider[@Name='Windows Defender'] and (Level=2 or Level=3) and (EventID=1005 or ...)]]

on Microsoft-Windows-Windows Defender/Operational. The provider that writes that log is
"Microsoft-Windows-Windows Defender" (Events/README.md already lists it that way):

    PS> Get-WinEvent -ListProvider *Defender*
    Microsoft-Windows-Windows Defender  (logs: Microsoft-Windows-Windows Defender/Operational, .../WHC)

Running the subscription's QueryList through Get-WinEvent -FilterXml on Windows 11 26200 returns
0 events, while the same log contains 3002, 5008, 2001 and 2004 events from
Microsoft-Windows-Windows Defender. With the provider name corrected the same query returns them.

The query also omits 1116 (detection, Warning) and 1119 (critical remediation error, Error), which
Events/README.md recommends and which fall inside the query's Level=2 or Level=3 filter.
```

### PR

**Title:** Fix AppLocker event levels (#19) and DefenderErr provider name

```
Fixes #19 and the DefenderErr.xml provider name.

AppLocker (#19). RecommendedEvents.json, RecommendedEvents.csv and Events/README.md:
- 8004 and 8007 are Error ("was prevented from running") -> "AppLocker Block"
- 8003 and 8006 are Warning ("would have been prevented ... if enforced", audit only) -> "AppLocker Warning"
- 8002 is Information ("was allowed to run") -> its own "Executable or DLL ran" row, like 8005
  "Script or Installer ran"
Source: https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/using-event-viewer-with-applocker
and the provider manifest (Get-WinEvent -ListProvider Microsoft-Windows-AppLocker).

DefenderErr.xml (NT6 and samples). The query filtered Provider[@Name='Windows Defender']; the
provider is Microsoft-Windows-Windows Defender, as Events/README.md says, so the subscription
forwarded nothing. Also adds 1116 and 1119, which the README recommends and which match the
existing Level=2 or Level=3 filter.

Tested on Windows 11 (10.0.26200) by passing the QueryList to Get-WinEvent -FilterXml:
before 0 events, after 14 (1116, 2001, 2004, 3002, 5008). The JSON still parses and the three
tables agree on the changed rows.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
```

Optional second issue, from the suite: `WinUpdateErr.xml` filters `Level=2`, but 34 and 35 are Warning in the WindowsUpdateClient manifest, and `samples/ServiceManager.xml` selects 7045 at `Level=1`. In both cases those events are never forwarded.

## 6. Land probability

**Low.** The fix is small, sourced and correct, but the repo has merged nothing since 2019-04 and has left #12/#16/#18 unanswered for 6+ years.

What the owner should do next:
1. File the Defender issue above, then open the PR from `fix/19-applocker-levels-defender-provider`. Both texts are paste-ready.
2. Treat `lane/modern-wef` as the fork's showcase. It is the only maintained, CI-checked Sigma mapping of the NSA list, with modern subscriptions validated against a real Windows event log service. Consider making it the fork's default branch or linking it from the fork description.
3. When a Windows host is upgraded, optionally re-run `pwsh tools/Export-WinEventSnapshot.ps1` elevated and review the changes to `tests/data/win-snapshot.json`.
