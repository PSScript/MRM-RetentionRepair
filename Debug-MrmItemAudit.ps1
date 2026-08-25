#Requires -Version 5.1
<#
.SYNOPSIS
Diagnostic for the item audit: runs FindItems against ONE folder in several
variants and prints exactly what each returns. READ-ONLY.

.EXAMPLE
    ./Debug-MrmItemAudit.ps1 -ConfigPath ./configs/kind.json
    ./Debug-MrmItemAudit.ps1 -ConfigPath ./configs/kind.json -FolderPath '/Aktenschrank/Kunden/Brasilien'
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ConfigPath,
    [string]$FolderPath
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'MRM-RetentionRepair.psm1') -Force

$cfg = Get-MrmConfig -Path $ConfigPath
$token = Get-MrmAccessToken -TenantId $cfg.TenantId -ClientId $cfg.ClientId `
            -ClientSecret $cfg.ClientSecret -Scope 'https://outlook.office365.com/.default'
$service = Connect-MrmEwsService -Mailbox $cfg.Mailbox -AccessToken $token
$census  = @(Get-MrmFolderCensus -Service $service)

$folder = if ($FolderPath) { $census | Where-Object FolderPath -eq $FolderPath | Select-Object -First 1 }
          else { $census | Where-Object { $_.ItemCount -gt 0 } | Sort-Object ItemCount -Descending | Select-Object -First 1 }
if (-not $folder) { throw "Folder not found in census. Use -FolderPath with a value from the census CSV." }

Write-Host ""
Write-Host "Folder    : $($folder.FolderPath)"
Write-Host "FolderId  : $($folder.FolderId.Substring(0,40))..."
Write-Host "ItemCount : $($folder.ItemCount)"
Write-Host ""

$props = Get-MrmEwsPropertyDefinitions
$fid   = [Microsoft.Exchange.WebServices.Data.FolderId]::new($folder.FolderId)

function Show-Result {
    param([string]$Label, [scriptblock]$Call)
    Write-Host ("=== {0} ===" -f $Label) -ForegroundColor Cyan
    try {
        $r = & $Call
        if ($null -eq $r) { Write-Host "  RESULT: `$null" -ForegroundColor Red }
        else {
            Write-Host ("  RESULT: {0}" -f $r.GetType().FullName) -ForegroundColor Green
            $hasItems = [bool]$r.PSObject.Properties['Items']
            Write-Host ("  has .Items : {0}" -f $hasItems)
            if ($hasItems) { Write-Host ("  .Items.Count: {0}   TotalCount: {1}" -f $r.Items.Count, $r.TotalCount) }
        }
    }
    catch { Write-Host ("  EXCEPTION: {0}" -f $_.Exception.Message) -ForegroundColor Red }
    Write-Host ""
}

# A: plain, no filter, minimal property set
$v1 = [Microsoft.Exchange.WebServices.Data.ItemView]::new(10, 0)
Show-Result -Label 'A: FindItems(folderId, view) - no filter, default props' -Call { $service.FindItems($fid, $v1) }

# B: with the Exists(PR_POLICY_TAG) filter, minimal property set
$v2 = [Microsoft.Exchange.WebServices.Data.ItemView]::new(10, 0)
$filter = [Microsoft.Exchange.WebServices.Data.SearchFilter+Exists]::new($props.PolicyTag)
Show-Result -Label 'B: FindItems(folderId, Exists(0x3019), view) - default props' -Call { $service.FindItems($fid, $filter, $v2) }

# C: the exact property set the audit uses (this is the suspect)
$v3 = [Microsoft.Exchange.WebServices.Data.ItemView]::new(10, 0)
$ps  = [Microsoft.Exchange.WebServices.Data.PropertySet]::new(
    [Microsoft.Exchange.WebServices.Data.BasePropertySet]::IdOnly,
    [Microsoft.Exchange.WebServices.Data.ItemSchema]::DateTimeReceived,
    [Microsoft.Exchange.WebServices.Data.ItemSchema]::DateTimeCreated)
$ps.Add($props.PolicyTag); $ps.Add($props.RetentionPeriod); $ps.Add($props.RetentionFlags)
$v3.PropertySet = $ps
Show-Result -Label 'C: FindItems + filter + audit PropertySet (extended props)' -Call { $service.FindItems($fid, $filter, $v3) }

# D: same as C but IdOnly - isolates whether the extended props are the problem
$v4 = [Microsoft.Exchange.WebServices.Data.ItemView]::new(10, 0)
$v4.PropertySet = [Microsoft.Exchange.WebServices.Data.PropertySet]::new(
    [Microsoft.Exchange.WebServices.Data.BasePropertySet]::IdOnly)
Show-Result -Label 'D: FindItems + filter + IdOnly PropertySet' -Call { $service.FindItems($fid, $filter, $v4) }

Write-Host "Send this whole output back. A/B/C/D pinpoint which element breaks." -ForegroundColor Cyan
