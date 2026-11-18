<#
.SYNOPSIS
    Run every subscription's QueryList through Get-WinEvent -FilterXml on this machine.

.DESCRIPTION
    Read-only. For each Subscriptions/**/*.xml the QueryList inside <Query><![CDATA[...]]> is
    passed to Get-WinEvent -FilterXml. The event log service parses the XPath and resolves every
    channel, so this is the same validation a Windows Event Collector applies.

    Result per file:
      MATCH         query is valid and matched at least one local event
      NOEVENTS      query is valid, no matching events on this machine
      NOCHANNEL     a channel in the query does not exist on this machine (warning)
      DENIED        reading a channel needs elevation (Security log); run as administrator
      INVALID       the event log service rejected the query (failure)

    Exits 1 if any query is INVALID, or if -FailOnMissingChannel is set and any is NOCHANNEL.
    -RequireMatch lists files that must return at least one event (used to prove a fix).
#>
param(
    [string]$Path = (Join-Path (Split-Path -Parent $PSScriptRoot) 'Subscriptions'),
    [int]$MaxEvents = 1,
    [switch]$FailOnMissingChannel,
    [string[]]$RequireMatch = @()
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$failed = $false
$results = foreach ($file in Get-ChildItem -LiteralPath $Path -Recurse -Filter *.xml | Sort-Object FullName) {
    $rel = [System.IO.Path]::GetRelativePath($root, $file.FullName) -replace '\\', '/'
    [xml]$sub = Get-Content -Raw -LiteralPath $file.FullName
    $query = ($sub.Subscription.Query.'#cdata-section').Trim()
    $status = 'MATCH'; $detail = ''; $count = 0
    try {
        $count = @(Get-WinEvent -FilterXml ([xml]$query) -MaxEvents $MaxEvents -ErrorAction Stop).Count
    } catch {
        $msg = $_.Exception.Message
        switch -Regex ($msg) {
            'No events were found' { $status = 'NOEVENTS'; break }
            'There is not an event log' { $status = 'NOCHANNEL'; $detail = $msg; break }
            'unauthorized|Access is denied' { $status = 'DENIED'; $detail = $msg; break }
            default { $status = 'INVALID'; $detail = $msg }
        }
    }
    if ($status -eq 'INVALID') { $failed = $true }
    if ($status -eq 'NOCHANNEL' -and $FailOnMissingChannel) { $failed = $true }
    if ($RequireMatch -contains $rel -and $status -ne 'MATCH') { $failed = $true; $detail = "required to match; $detail" }
    [pscustomobject]@{ Status = $status; File = $rel; Detail = $detail.Trim() }
}
$results | Format-Table -AutoSize -Wrap | Out-String -Width 220
$results | Group-Object Status | ForEach-Object { '{0,-9} {1}' -f $_.Name, $_.Count }
if ($failed) { exit 1 }
