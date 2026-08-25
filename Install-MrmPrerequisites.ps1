#Requires -Version 5.1
<#
.SYNOPSIS
Installs the EWS Managed API from nuget.org into a stable location outside the
repo, unblocks it, and verifies it actually loads.

.DESCRIPTION
Install location, in preference order:
  1. an existing official MSI install (Program Files\Microsoft\Exchange\Web Services\2.2)
     - reused, never duplicated
  2. %ProgramData%\MRM-RetentionRepair\lib   (machine-wide; requires elevation)
  3. %LOCALAPPDATA%\MRM-RetentionRepair\lib  (per-user fallback)
  4. .\lib                                   (portable fallback)

Run elevated for the machine-wide location; otherwise it installs per-user,
which works fine for a single operator.

.EXAMPLE
    ./Install-MrmPrerequisites.ps1
.EXAMPLE
    ./Install-MrmPrerequisites.ps1 -Version 2.2.0 -Force
.EXAMPLE
    ./Install-MrmPrerequisites.ps1 -WhatIfPathsOnly     # just show what would be used
#>
[CmdletBinding()]
param(
    [string]$Version = '2.2.0',
    [string]$Destination,
    [switch]$Force,
    [switch]$WhatIfPathsOnly
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'MRM-RetentionRepair.psm1') -Force

$paths = Get-MrmEwsInstallPath -ForWrite
Write-Host ''
Write-Host '=============== EWS Managed API - install locations ===============' -ForegroundColor Cyan
Write-Host ("  Official MSI install : {0}" -f $(if ($paths.MsiPath) { $paths.MsiPath } else { '<not installed>' }))
Write-Host ("  Machine-wide dir     : {0}" -f $(if ($paths.MachineDir) { $paths.MachineDir } else { '<n/a>' }))
Write-Host ("  Per-user dir         : {0}" -f $(if ($paths.UserDir) { $paths.UserDir } else { '<n/a>' }))
Write-Host ("  Repo-local dir       : {0}" -f $paths.RepoDir)
Write-Host ("  Elevated             : {0}" -f $paths.IsElevated)
Write-Host ("  Would install to     : {0}" -f $(if ($Destination) { $Destination } else { $paths.WriteDir }))
if (-not $paths.IsElevated -and $paths.MachineDir) {
    Write-Host '  (not elevated - installing per-user; run as admin for a machine-wide install)' -ForegroundColor Yellow
}
Write-Host ''

if ($WhatIfPathsOnly) {
    Write-Host 'Search order used at runtime:' -ForegroundColor Cyan
    $i = 0
    foreach ($p in $paths.SearchOrder) {
        $i++
        Write-Host ("   {0}. [{1}] {2}" -f $i, $(if (Test-Path $p) { 'present' } else { 'missing' }), $p)
    }
    return
}

$splat = @{ Version = $Version; Force = $Force }
if ($Destination) { $splat.Destination = $Destination }
$dll = Install-MrmEwsManagedApi @splat

# Proof, not assumption: load it and resolve the types the tool actually uses.
Import-MrmEwsAssembly -Path $dll
$required = @(
    'Microsoft.Exchange.WebServices.Data.ExchangeService',
    'Microsoft.Exchange.WebServices.Data.OAuthCredentials',
    'Microsoft.Exchange.WebServices.Data.ExtendedPropertyDefinition',
    'Microsoft.Exchange.WebServices.Data.FolderSchema'
)
$missing = @($required | Where-Object { -not ($_ -as [type]) })
if ($missing) { throw "Assembly loaded but these types are missing: $($missing -join ', ')" }

# The PolicyTag property is what the whole repair depends on - check explicitly.
$hasPolicyTag = [bool]([Microsoft.Exchange.WebServices.Data.FolderSchema] | Get-Member -Static -Name PolicyTag)

Write-Host ''
Write-Host "[ok] EWS Managed API ${Version} ready: ${dll}" -ForegroundColor Green
Write-Host "[ok] all required types resolve" -ForegroundColor Green
Write-Host ("[{0}] FolderSchema::PolicyTag available (required for the untag operation)" -f $(if ($hasPolicyTag) { 'ok' } else { '!!' })) -ForegroundColor $(if ($hasPolicyTag) { 'Green' } else { 'Red' })
Write-Host ''
Write-Host 'Next: ./Manage-MrmConfig.ps1 -Action Test -ConfigPath ./configs/<name>.json' -ForegroundColor Cyan
