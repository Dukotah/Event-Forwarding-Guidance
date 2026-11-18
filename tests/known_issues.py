"""Known problems in the upstream data, recorded so the suite is green and any change shows up.

Each set must match exactly what tests/checks.py finds. If you fix one of these, delete it here.
Regenerate the snapshot with tools/Export-WinEventSnapshot.ps1 before editing manifest-based entries.
"""

# Rows that differ between RecommendedEvents.json, RecommendedEvents.csv and Events/README.md.
# - JSON calls a category "Network Policy" / "Windows Defender Activities"; README says
#   "Network Host Activities" / "Windows Defender Antivirus Activities".
# - README names the provider "Microsoft-Windows-CertificateServicesClientLifecycle-System" (upstream issue #14, PR #16)
#   and lists rows the JSON does not have (cert lifecycle 1001-1007, System Time Changed 4616).
# - CSV lists CA 90 (JSON has 95), a single "Exception Raised" name for 4104-4106 (JSON has three names),
#   and omits the Pass the Hash / Remote Desktop rows, which use a different schema in the JSON.
TABLE_DIFFERENCES = {
    'csv-not-json: Certificate Services | CA Permissions Corrupted or Missing | 90 | Information | Microsoft-Windows-CertificationAuthority | Microsoft-Windows-CertificationAuthority',
    'csv-not-json: PowerShell Activities | Exception Raised | 4104 | Information | Microsoft-Windows-Powershell/Operational | Microsoft-Windows-Powershell',
    'csv-not-json: PowerShell Activities | Exception Raised | 4105 | Information | Microsoft-Windows-Powershell/Operational | Microsoft-Windows-Powershell',
    'csv-not-json: PowerShell Activities | Exception Raised | 4106 | Information | Microsoft-Windows-Powershell/Operational | Microsoft-Windows-Powershell',
    'json-not-csv: Certificate Services | CA Permissions Corrupted or Missing | 95 | Error | Application | Microsoft-Windows-CertificationAuthority',
    'json-not-csv: Pass the Hash Detection | Detect Pass the Hash | 4624 | Information | Security | ',
    'json-not-csv: Pass the Hash Detection | Detect Pass the Hash | 4625 | Information | Security | ',
    'json-not-csv: PowerShell Activities | Script block contents | 4104 | Information | Microsoft-Windows-Powershell/Operational | Microsoft-Windows-Powershell',
    'json-not-csv: PowerShell Activities | Script block end | 4106 | Information | Microsoft-Windows-Powershell/Operational | Microsoft-Windows-Powershell',
    'json-not-csv: PowerShell Activities | Script block start | 4105 | Information | Microsoft-Windows-Powershell/Operational | Microsoft-Windows-Powershell',
    'json-not-csv: Remote Desktop Logon Detection | Remote Desktop Logon Detection | 4624 | Information | Security | ',
    'json-not-csv: Remote Desktop Logon Detection | Remote Desktop Logon Detection | 4634 | Information | Security | ',
    'json-not-readme: Network Policy | Encrypted Data Recovery Policy Changed | 4714 | Information | Security | Microsoft-Windows-Security-Auditing',
    'json-not-readme: Network Policy | Kerberos Policy Changed | 4713 | Information | Security | Microsoft-Windows-Security-Auditing',
    'json-not-readme: Network Policy | Kerberos Service Ticket Req. Failed | 4769 | Information | Security | Microsoft-Windows-Security-Auditing',
    'json-not-readme: Network Policy | Network Policy Server Denied Access | 6273 | Information | Security | Microsoft-Windows-Security-Auditing',
    'json-not-readme: Network Policy | Network Policy Server Discarded Accounting Request | 6275 | Information | Security | Microsoft-Windows-Security-Auditing',
    'json-not-readme: Network Policy | Network Policy Server Discarded Request | 6274 | Information | Security | Microsoft-Windows-Security-Auditing',
    'json-not-readme: Network Policy | Network Policy Server Granted Access | 6272 | Information | Security | Microsoft-Windows-Security-Auditing',
    'json-not-readme: Network Policy | Network Policy Server Granted Full Access | 6278 | Information | Security | Microsoft-Windows-Security-Auditing',
    'json-not-readme: Network Policy | Network Policy Server Granted Probationary Access | 6277 | Information | Security | Microsoft-Windows-Security-Auditing',
    'json-not-readme: Network Policy | Network Policy Server Locked Account | 6279 | Information | Security | Microsoft-Windows-Security-Auditing',
    'json-not-readme: Network Policy | Network Policy Server Quarantined User | 6276 | Information | Security | Microsoft-Windows-Security-Auditing',
    'json-not-readme: Network Policy | Network Policy Server Unlocked Account | 6280 | Information | Security | Microsoft-Windows-Security-Auditing',
    'json-not-readme: Network Policy | Network Share Checked | 5145 | Information | Security | Microsoft-Windows-Security-Auditing',
    'json-not-readme: Network Policy | Network Share Created | 5142 | Information | Security | Microsoft-Windows-Security-Auditing',
    'json-not-readme: Network Policy | Network Share Deleted | 5144 | Information | Security | Microsoft-Windows-Security-Auditing',
    'json-not-readme: Network Policy | Network share accessed | 5140 | Information | Security | Microsoft-Windows-Security-Auditing',
    'json-not-readme: Network Policy | New Trust for Domain | 4706 | Information | Security | Microsoft-Windows-Security-Auditing',
    'json-not-readme: Network Policy | Outbound TS Connect Attempt | 1024 | Information | Microsoft-Windows-TerminalServices-RDPClient/Operational | Microsoft-Windows-TerminalServices-ClientActiveXCore',
    'json-not-readme: Network Policy | RADIUS User Authenticated | 20274 | Success | RemoteAccess | Microsoft-Windows-MPRMSG',
    'json-not-readme: Network Policy | RADIUS User Disconnected | 20275 | Success | RemoteAccess | Microsoft-Windows-MPRMSG',
    'json-not-readme: Network Policy | RADIUS User assigned IP | 20250 | Success | RemoteAccess | Microsoft-Windows-MPRMSG',
    'json-not-readme: Network Policy | Role Separation Enabled | 4897 | Information | Security | Microsoft-Windows-Security-Auditing',
    'json-not-readme: Network Policy | System Audit Policy Changed | 4719 | Information | Security | Microsoft-Windows-Security-Auditing',
    'json-not-readme: Network Policy | TS Session Disconnect | 4779 | Information | Security | Microsoft-Windows-Security-Auditing',
    'json-not-readme: Network Policy | TS Session Reconnect | 4778 | Information | Security | Microsoft-Windows-Security-Auditing',
    'json-not-readme: Network Policy | Trusted Domain Information Modified | 4716 | Information | Security | Microsoft-Windows-Security-Auditing',
    'json-not-readme: Network Policy | Wireless 802.1X Auth | 5632 | Information | Security | Microsoft-Windows-Security-Auditing',
    'json-not-readme: Pass the Hash Detection | Detect Pass the Hash | 4624 | Information | Security | ',
    'json-not-readme: Pass the Hash Detection | Detect Pass the Hash | 4625 | Information | Security | ',
    'json-not-readme: Remote Desktop Logon Detection | Remote Desktop Logon Detection | 4624 | Information | Security | ',
    'json-not-readme: Remote Desktop Logon Detection | Remote Desktop Logon Detection | 4634 | Information | Security | ',
    'json-not-readme: Windows Defender Activities | Action on Malware Failed | 1008 | Error | Microsoft-Windows-Windows Defender/Operational | Microsoft-Windows-Windows Defender',
    'json-not-readme: Windows Defender Activities | Detected Malware | 1006, 1116 | Warning | Microsoft-Windows-Windows Defender/Operational | Microsoft-Windows-Windows Defender',
    'json-not-readme: Windows Defender Activities | Failed to remove item from quarantine | 1010 | Error | Microsoft-Windows-Windows Defender/Operational | Microsoft-Windows-Windows Defender',
    'json-not-readme: Windows Defender Activities | Failed to update engine | 2003 | Error | Microsoft-Windows-Windows Defender/Operational | Microsoft-Windows-Windows Defender',
    'json-not-readme: Windows Defender Activities | Failed to update signatures | 2001 | Error | Microsoft-Windows-Windows Defender/Operational | Microsoft-Windows-Windows Defender',
    'json-not-readme: Windows Defender Activities | File Restored from Quarantine | 1009 | Information | Microsoft-Windows-Windows Defender/Operational | Microsoft-Windows-Windows Defender',
    'json-not-readme: Windows Defender Activities | Malware Removal Error | 1118 | Information | Microsoft-Windows-Windows Defender/Operational | Microsoft-Windows-Windows Defender',
    'json-not-readme: Windows Defender Activities | Malware Removal Fatal Error | 1119 | Error | Microsoft-Windows-Windows Defender/Operational | Microsoft-Windows-Windows Defender',
    'json-not-readme: Windows Defender Activities | Malware Removed | 1007, 1117 | Information | Microsoft-Windows-Windows Defender/Operational | Microsoft-Windows-Windows Defender',
    'json-not-readme: Windows Defender Activities | Real-Time Protection failed | 3002 | Error | Microsoft-Windows-Windows Defender/Operational | Microsoft-Windows-Windows Defender',
    'json-not-readme: Windows Defender Activities | Reverting to last known good set of signatures | 2004 | Warning | Microsoft-Windows-Windows Defender/Operational | Microsoft-Windows-Windows Defender',
    'json-not-readme: Windows Defender Activities | Scan Failed | 1005 | Error | Microsoft-Windows-Windows Defender/Operational | Microsoft-Windows-Windows Defender',
    'json-not-readme: Windows Defender Activities | Unexpected Error | 5008 | Error | Microsoft-Windows-Windows Defender/Operational | Microsoft-Windows-Windows Defender',
    'readme-not-json: Certificate Services | Certificate close to expiration | 1003 | Warning | Microsoft-Windows-CertificateServicesClientLifecycle-System/Operational | Microsoft-Windows-CertificateServicesClientLifecycle-System',
    'readme-not-json: Certificate Services | Expired Certificate | 1002 | Error | Microsoft-Windows-CertificateServicesClientLifecycle-System/Operational | Microsoft-Windows-CertificateServicesClientLifecycle-System',
    'readme-not-json: Certificate Services | Exported Certificate | 1007 | Information | Microsoft-Windows-CertificateServicesClientLifecycle-System/Operational | Microsoft-Windows-CertificateServicesClientLifecycle-System',
    'readme-not-json: Certificate Services | Import Certificate | 1006 | Information | Microsoft-Windows-CertificateServicesClientLifecycle-System/Operational | Microsoft-Windows-CertificateServicesClientLifecycle-System',
    'readme-not-json: Certificate Services | Remove Certificate | 1004 | Information | Microsoft-Windows-CertificateServicesClientLifecycle-System/Operational | Microsoft-Windows-CertificateServicesClientLifecycle-System',
    'readme-not-json: Certificate Services | Replace Certificate | 1001 | Information | Microsoft-Windows-CertificateServicesClientLifecycle-System/Operational | Microsoft-Windows-CertificateServicesClientLifecycle-System',
    'readme-not-json: Network Host Activities | Encrypted Data Recovery Policy Changed | 4714 | Information | Security | Microsoft-Windows-Security-Auditing',
    'readme-not-json: Network Host Activities | Kerberos Policy Changed | 4713 | Information | Security | Microsoft-Windows-Security-Auditing',
    'readme-not-json: Network Host Activities | Kerberos Service Ticket Req. Failed | 4769 | Information | Security | Microsoft-Windows-Security-Auditing',
    'readme-not-json: Network Host Activities | Network Policy Server Denied Access | 6273 | Information | Security | Microsoft-Windows-Security-Auditing',
    'readme-not-json: Network Host Activities | Network Policy Server Discarded Accounting Request | 6275 | Information | Security | Microsoft-Windows-Security-Auditing',
    'readme-not-json: Network Host Activities | Network Policy Server Discarded Request | 6274 | Information | Security | Microsoft-Windows-Security-Auditing',
    'readme-not-json: Network Host Activities | Network Policy Server Granted Access | 6272 | Information | Security | Microsoft-Windows-Security-Auditing',
    'readme-not-json: Network Host Activities | Network Policy Server Granted Full Access | 6278 | Information | Security | Microsoft-Windows-Security-Auditing',
    'readme-not-json: Network Host Activities | Network Policy Server Granted Probationary Access | 6277 | Information | Security | Microsoft-Windows-Security-Auditing',
    'readme-not-json: Network Host Activities | Network Policy Server Locked Account | 6279 | Information | Security | Microsoft-Windows-Security-Auditing',
    'readme-not-json: Network Host Activities | Network Policy Server Quarantined User | 6276 | Information | Security | Microsoft-Windows-Security-Auditing',
    'readme-not-json: Network Host Activities | Network Policy Server Unlocked Account | 6280 | Information | Security | Microsoft-Windows-Security-Auditing',
    'readme-not-json: Network Host Activities | Network Share Checked | 5145 | Information | Security | Microsoft-Windows-Security-Auditing',
    'readme-not-json: Network Host Activities | Network Share Created | 5142 | Information | Security | Microsoft-Windows-Security-Auditing',
    'readme-not-json: Network Host Activities | Network Share Deleted | 5144 | Information | Security | Microsoft-Windows-Security-Auditing',
    'readme-not-json: Network Host Activities | Network share accessed | 5140 | Information | Security | Microsoft-Windows-Security-Auditing',
    'readme-not-json: Network Host Activities | New Trust for Domain | 4706 | Information | Security | Microsoft-Windows-Security-Auditing',
    'readme-not-json: Network Host Activities | Outbound TS Connect Attempt | 1024 | Information | Microsoft-Windows-TerminalServices-RDPClient/Operational | Microsoft-Windows-TerminalServices-ClientActiveXCore',
    'readme-not-json: Network Host Activities | RADIUS User Authenticated | 20274 | Success | RemoteAccess | Microsoft-Windows-MPRMSG',
    'readme-not-json: Network Host Activities | RADIUS User Disconnected | 20275 | Success | RemoteAccess | Microsoft-Windows-MPRMSG',
    'readme-not-json: Network Host Activities | RADIUS User assigned IP | 20250 | Success | RemoteAccess | Microsoft-Windows-MPRMSG',
    'readme-not-json: Network Host Activities | Role Separation Enabled | 4897 | Information | Security | Microsoft-Windows-Security-Auditing',
    'readme-not-json: Network Host Activities | System Audit Policy Changed | 4719 | Information | Security | Microsoft-Windows-Security-Auditing',
    'readme-not-json: Network Host Activities | TS Session Disconnect | 4779 | Information | Security | Microsoft-Windows-Security-Auditing',
    'readme-not-json: Network Host Activities | TS Session Reconnect | 4778 | Information | Security | Microsoft-Windows-Security-Auditing',
    'readme-not-json: Network Host Activities | Trusted Domain Information Modified | 4716 | Information | Security | Microsoft-Windows-Security-Auditing',
    'readme-not-json: Network Host Activities | Wireless 802.1X Auth | 5632 | Information | Security | Microsoft-Windows-Security-Auditing',
    'readme-not-json: System Integrity | System Time Changed | 4616 | Information | Security | Microsoft-Windows-Security-Auditing',
    'readme-not-json: Windows Defender Antivirus Activities | Action on Malware Failed | 1008 | Error | Microsoft-Windows-Windows Defender/Operational | Microsoft-Windows-Windows Defender',
    'readme-not-json: Windows Defender Antivirus Activities | Detected Malware | 1006, 1116 | Warning | Microsoft-Windows-Windows Defender/Operational | Microsoft-Windows-Windows Defender',
    'readme-not-json: Windows Defender Antivirus Activities | Failed to remove item from quarantine | 1010 | Error | Microsoft-Windows-Windows Defender/Operational | Microsoft-Windows-Windows Defender',
    'readme-not-json: Windows Defender Antivirus Activities | Failed to update engine | 2003 | Error | Microsoft-Windows-Windows Defender/Operational | Microsoft-Windows-Windows Defender',
    'readme-not-json: Windows Defender Antivirus Activities | Failed to update signatures | 2001 | Error | Microsoft-Windows-Windows Defender/Operational | Microsoft-Windows-Windows Defender',
    'readme-not-json: Windows Defender Antivirus Activities | File Restored from Quarantine | 1009 | Information | Microsoft-Windows-Windows Defender/Operational | Microsoft-Windows-Windows Defender',
    'readme-not-json: Windows Defender Antivirus Activities | Malware Removal Error | 1118 | Information | Microsoft-Windows-Windows Defender/Operational | Microsoft-Windows-Windows Defender',
    'readme-not-json: Windows Defender Antivirus Activities | Malware Removal Fatal Error | 1119 | Error | Microsoft-Windows-Windows Defender/Operational | Microsoft-Windows-Windows Defender',
    'readme-not-json: Windows Defender Antivirus Activities | Malware Removed | 1007, 1117 | Information | Microsoft-Windows-Windows Defender/Operational | Microsoft-Windows-Windows Defender',
    'readme-not-json: Windows Defender Antivirus Activities | Real-Time Protection failed | 3002 | Error | Microsoft-Windows-Windows Defender/Operational | Microsoft-Windows-Windows Defender',
    'readme-not-json: Windows Defender Antivirus Activities | Reverting to last known good set of signatures | 2004 | Warning | Microsoft-Windows-Windows Defender/Operational | Microsoft-Windows-Windows Defender',
    'readme-not-json: Windows Defender Antivirus Activities | Scan Failed | 1005 | Error | Microsoft-Windows-Windows Defender/Operational | Microsoft-Windows-Windows Defender',
    'readme-not-json: Windows Defender Antivirus Activities | Unexpected Error | 5008 | Error | Microsoft-Windows-Windows Defender/Operational | Microsoft-Windows-Windows Defender',
}

# Event Log values in RecommendedEvents.json that are not a channel on Windows 11 26200.
# - User32 is a provider that writes to System; "Powershell" is the "Windows PowerShell" log.
# - Kernel-PnP/Device Configuration: the channel is Microsoft-Windows-Kernel-PnP/Configuration.
# - DNSServer/Analytical and RemoteAccess exist only on servers with the DNS / RRAS roles.
RECOMMENDED_UNKNOWN_CHANNELS = {
    'Boot Events | Shutdown Initiate Failed: User32',
    'DNS/Directory Services | DNS Request/Response: Microsoft-Windows-DNSServer/Analytical',
    'External Media Detection | New Mass Storage Installation: Microsoft-Windows-Kernel-PnP/Device Configuration',
    'Network Policy | RADIUS User Authenticated: RemoteAccess',
    'Network Policy | RADIUS User Disconnected: RemoteAccess',
    'Network Policy | RADIUS User assigned IP: RemoteAccess',
    'PowerShell Activities | Get-MessageTrackingLog cmdlet: Powershell',
    'PowerShell Activities | Remote Connection: Powershell',
}

# Server-role providers, absent on a Windows 11 client.
RECOMMENDED_UNKNOWN_PROVIDERS = {
    'Microsoft-Windows-CertificationAuthority',
    'Microsoft-Windows-DNSServer',
}

# Documented level or ID differs from the provider manifest on Windows 11 26200.
# - 7045 is attributed to Microsoft-Windows-FilterManager; it is written by Service Control Manager (upstream issue #13, PR #12).
# - 4104-4106 are Verbose in the manifest (4104 is raised to Warning for suspicious script blocks).
# - WindowsUpdateClient 34/35 are Warning, Defender 2004 is Error, WLAN 11010 is Information.
# - MPRMSG 20xxx, PowerShell 169/800 and Servicing 2/1009 are classic or message-table events not in the manifest.
RECOMMENDED_LEVEL_MISMATCHES = {
    'Mobile Device Activities | Wireless Security Started, Stopped, Successful, or Failed: 11010 documented Error, manifest Information',
    'Network Policy | RADIUS User Authenticated: Microsoft-Windows-MPRMSG 20274 not in manifest',
    'Network Policy | RADIUS User Disconnected: Microsoft-Windows-MPRMSG 20275 not in manifest',
    'Network Policy | RADIUS User assigned IP: Microsoft-Windows-MPRMSG 20250 not in manifest',
    'PowerShell Activities | Get-MessageTrackingLog cmdlet: Microsoft-Windows-Powershell 800 not in manifest',
    'PowerShell Activities | Remote Connection: Microsoft-Windows-Powershell 169 not in manifest',
    'PowerShell Activities | Script block contents: 4104 documented Information, manifest Verbose',
    'PowerShell Activities | Script block end: 4106 documented Information, manifest Verbose',
    'PowerShell Activities | Script block start: 4105 documented Information, manifest Verbose',
    'Software and Service Installation | New Windows Service: Microsoft-Windows-FilterManager 7045 not in manifest',
    'Software and Service Installation | Update Packages Installed: Microsoft-Windows-Servicing 2 not in manifest',
    'Windows Defender Activities | Reverting to last known good set of signatures: 2004 documented Warning, manifest Error',
    'Windows Update Errors | Hotpatching Failed: Microsoft-Windows-Servicing 1009 not in manifest',
    'Windows Update Errors | Windows Update Failed: 34 documented Error, manifest Warning',
    'Windows Update Errors | Windows Update Failed: 35 documented Error, manifest Warning',
}

XPATH_PROBLEMS = set()

SUBSCRIPTION_UNKNOWN_CHANNELS = set()

# EMET reached end of support in July 2018; see Subscriptions/modern/ExploitProtection.xml.
SUBSCRIPTION_UNKNOWN_PROVIDERS = {
    'Subscriptions/NT6/EMETLogs.xml: EMET',
    'Subscriptions/samples/EMETLogs.xml: EMET',
}

SUBSCRIPTION_UNKNOWN_EVENT_IDS = set()

# WinUpdateErr.xml selects Level=2 but WindowsUpdateClient writes 34 and 35 at Warning (3),
# so those two IDs are never forwarded.
SUBSCRIPTION_LEVEL_FILTER_EXCLUDES = {
    "Subscriptions/NT6/WinUpdateErr.xml: Microsoft-Windows-WindowsUpdateClient 34 is Warning, filter allows ['Error']",
    "Subscriptions/NT6/WinUpdateErr.xml: Microsoft-Windows-WindowsUpdateClient 35 is Warning, filter allows ['Error']",
    "Subscriptions/samples/WinUpdateErr.xml: Microsoft-Windows-WindowsUpdateClient 34 is Warning, filter allows ['Error']",
    "Subscriptions/samples/WinUpdateErr.xml: Microsoft-Windows-WindowsUpdateClient 35 is Warning, filter allows ['Error']",
}

# Event IDs a subscription forwards that RecommendedEvents.json does not list.
# - Service Control Manager 7045: the JSON attributes 7045 to FilterManager (upstream issue #13).
# - LSA Protection.xml, GroupPolicy 1127 and EMET 1/2 are simply not in the recommended table.
SUBSCRIPTION_IDS_NOT_RECOMMENDED = {
    'Subscriptions/LSA Protection.xml: Microsoft-Windows-CodeIntegrity 3033',
    'Subscriptions/LSA Protection.xml: Microsoft-Windows-CodeIntegrity 3063',
    'Subscriptions/LSA Protection.xml: Microsoft-Windows-CodeIntegrity 3065',
    'Subscriptions/LSA Protection.xml: Microsoft-Windows-CodeIntegrity 3066',
    'Subscriptions/LSA Protection.xml: Microsoft-Windows-Wininit 12',
    'Subscriptions/NT6/EMETLogs.xml: EMET 1',
    'Subscriptions/NT6/EMETLogs.xml: EMET 2',
    'Subscriptions/NT6/GrpPolicyErr.xml: Microsoft-Windows-GroupPolicy 1127',
    'Subscriptions/NT6/ServiceManager.xml: Service Control Manager 7045',
    'Subscriptions/samples/EMETLogs.xml: EMET 1',
    'Subscriptions/samples/EMETLogs.xml: EMET 2',
    'Subscriptions/samples/GrpPolicyErr.xml: Microsoft-Windows-GroupPolicy 1127',
    'Subscriptions/samples/ServiceManager.xml: Service Control Manager 7045',
}

# samples/ queries that differ from NT6/.
# - AccountLogons.xml: samples/ keeps one of the four Security selects.
# - ServiceManager.xml: samples/ selects 7045 with Level=1 (Critical); 7045 is written at
#   Information, so the samples/ subscription never forwards new-service events
#   (Get-WinEvent on Windows 11: Level=1 -> 0 events, Level=4 -> 117).
NT6_SAMPLES_DIFFER = {
    "AccountLogons.xml",
    "ServiceManager.xml",
}
