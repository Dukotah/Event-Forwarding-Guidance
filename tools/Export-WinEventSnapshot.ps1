<#
.SYNOPSIS
    Snapshot the event channels and provider manifests that this repository refers to.

.DESCRIPTION
    Read-only. Writes JSON with every channel name on this machine (EventLogSession.GetLogNames())
    and, for each provider named in Subscriptions/ or Events/RecommendedEvents.json, the event
    IDs and levels declared in its manifest (Get-WinEvent -ListProvider). The tests in tests/
    compare the repository's data files against this snapshot, so provider name typos and
    wrong levels are caught without a Windows host.

.EXAMPLE
    pwsh -File tools/Export-WinEventSnapshot.ps1 -OutFile tests/data/win-snapshot.json
#>
param(
    [string]$RepoRoot = (Split-Path -Parent $PSScriptRoot),
    [string]$OutFile = (Join-Path (Split-Path -Parent $PSScriptRoot) 'tests/data/win-snapshot.json')
)
$ErrorActionPreference = 'Stop'

$providers = [System.Collections.Generic.SortedSet[string]]::new()
Get-ChildItem -Path (Join-Path $RepoRoot 'Subscriptions') -Recurse -Filter *.xml | ForEach-Object {
    foreach ($m in [regex]::Matches((Get-Content -Raw -LiteralPath $_.FullName), "Provider\[@Name='([^']+)'\]")) {
        [void]$providers.Add($m.Groups[1].Value)
    }
}
$json = Get-Content -Raw (Join-Path $RepoRoot 'Events/RecommendedEvents.json') | ConvertFrom-Json -AsHashtable
foreach ($cat in $json['Recommended Events to Collect'].Values) {
    foreach ($name in $cat['events'].Values) {
        foreach ($ev in $name.Values) { if ($ev['eventsource']) { [void]$providers.Add($ev['eventsource']) } }
    }
}

$os = Get-CimInstance Win32_OperatingSystem
$snap = [ordered]@{
    generated = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd')
    os        = "$($os.Caption) $($os.Version)"
    # GetLogNames() lists every channel without opening it, so Security is included without elevation.
    channels  = @([System.Diagnostics.Eventing.Reader.EventLogSession]::GlobalSession.GetLogNames() | Sort-Object -Unique)
    providers = [ordered]@{}
    unresolved = @()
}
foreach ($p in $providers) {
    try { $meta = Get-WinEvent -ListProvider $p -ErrorAction Stop } catch { $snap.unresolved += $p; continue }
    $events = [ordered]@{}
    foreach ($e in ($meta.Events | Sort-Object Id, Version)) {
        $lvl = if ($e.Level -and $e.Level.DisplayName) { $e.Level.DisplayName.Trim([char[]]@([char]0, [char]32)) } else { $null }
        # Keep the highest manifest version of each ID.
        $events["$($e.Id)"] = $lvl
    }
    $snap.providers[$meta.Name] = [ordered]@{
        logs   = @($meta.LogLinks | ForEach-Object LogName)
        events = $events
    }
}
$text = ($snap | ConvertTo-Json -Depth 6) -replace "`r`n", "`n"
[System.IO.File]::WriteAllText($OutFile, $text + "`n", [System.Text.UTF8Encoding]::new($false))
"wrote $OutFile ($($snap.channels.Count) channels, $($snap.providers.Count) providers resolved of $($providers.Count) named)"
