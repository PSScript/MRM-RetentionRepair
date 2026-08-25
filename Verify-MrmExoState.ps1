#Requires -Version 5.1
<#
.SYNOPSIS
EXO-side verification, independent of the EWS tooling: extended folder
statistics and a Recoverable Items breakdown. READ-ONLY.

.DESCRIPTION
Run this in an Exchange Online PowerShell session (Connect-ExchangeOnline).
It deliberately does NOT use EWS - that is the point: it is an independent
second opinion on what the EWS census claims.

  1. Get-MailboxFolderStatistics -IncludeAnalysis, extended beyond
     FolderPath/DeletePolicy/RetentionFlags: item counts, sizes, oldest and
     newest item dates, archive policy - plus a summary per DeletePolicy.
  2. Get-RecoverableItems, grouped by LastParentPath and item type, with the
     deletion timeline. In Exchange Online it can be filtered by -PolicyTag,
     which answers "which of the deleted items carry OUR tag" directly.

Both write CSVs next to the EWS evidence so the two views can be compared.

NOTE ON COUNTS: Get-MailboxFolderStatistics reports the EFFECTIVE policy
(what the user sees, including inherited tags). The EWS census reports
PHYSICAL stamps. The two numbers are allowed to differ - that difference is
the whole point of the falsifier.

.EXAMPLE
    .\Verify-MrmExoState.ps1 -Mailbox user@contoso.com
.EXAMPLE
    .\Verify-MrmExoState.ps1 -Mailbox user@contoso.com `
        -PolicyTag d94993b5-e987-4275-8707-072057cfb2b8 -IncludeRecoverableItems
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Mailbox,
    [string]$DeletePolicyName = '6 Month Delete',
    [string]$PolicyTag,                       # RetentionId GUID, EXO only
    [switch]$IncludeRecoverableItems,
    [int]$RecoverableItemsMax = 50000,
    [string]$OutputDirectory = (Join-Path $PSScriptRoot 'evidence')
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

foreach ($c in 'Get-MailboxFolderStatistics','Get-Mailbox') {
    if (-not (Get-Command $c -ErrorAction SilentlyContinue)) {
        throw "${c} not available. Run Connect-ExchangeOnline first (this script does NOT use EWS)."
    }
}
New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'

# --- Mailbox state first: without this the numbers below cannot be read ------
Write-Host ''
Write-Host '=============== MAILBOX STATE ===============' -ForegroundColor Cyan
$mbx = Get-Mailbox -Identity $Mailbox
$mbx | Select-Object RetentionPolicy, ElcProcessingDisabled, RetentionHoldEnabled,
                     LitigationHoldEnabled, SingleItemRecoveryEnabled |
      Format-List | Out-String | Write-Host
if ($mbx.ElcProcessingDisabled) {
    Write-Host ' ElcProcessingDisabled = True: MFA does not process this mailbox AT ALL' -ForegroundColor Yellow
    Write-Host ' (including expiry in Recoverable Items). Numbers below are frozen.'     -ForegroundColor Yellow
}

# --- 1) Extended folder statistics ------------------------------------------
Write-Host ''
Write-Host '=============== FOLDER STATISTICS (effective policy) ===============' -ForegroundColor Cyan
$fs = @(Get-MailboxFolderStatistics -Identity $Mailbox -IncludeAnalysis |
        Select-Object FolderPath, DeletePolicy, ArchivePolicy, RetentionFlags,
                      ItemsInFolder, DeletedItemsInFolder, FolderSize,
                      ItemsInFolderAndSubfolders, FolderAndSubfolderSize,
                      OldestItemReceivedDate, NewestItemReceivedDate,
                      FolderType, ContainerClass)

$fsCsv = Join-Path $OutputDirectory "exo-folderstats-${stamp}.csv"
$fs | Export-Csv -Path $fsCsv -NoTypeInformation -Encoding utf8

Write-Host (" folders total                : {0}" -f $fs.Count)
Write-Host (" with DeletePolicy '{0}' : {1}" -f $DeletePolicyName,
            @($fs | Where-Object DeletePolicy -eq $DeletePolicyName).Count) -ForegroundColor Yellow
Write-Host ''
Write-Host ' by DeletePolicy:'
$fs | Group-Object DeletePolicy | Sort-Object Count -Descending |
    Select-Object @{n='DeletePolicy';e={ if ($_.Name) { $_.Name } else { '<none>' } }},
                  Count,
                  @{n='Items';e={ ($_.Group | Measure-Object ItemsInFolder -Sum).Sum }} |
    Format-Table -AutoSize | Out-String -Width 200 | Write-Host

Write-Host ' by RetentionFlags:'
$fs | Group-Object RetentionFlags | Sort-Object Count -Descending |
    Select-Object @{n='RetentionFlags';e={ if ($_.Name) { $_.Name } else { '<none>' } }}, Count |
    Format-Table -AutoSize | Out-String -Width 200 | Write-Host

$affected = @($fs | Where-Object DeletePolicy -eq $DeletePolicyName)
if ($affected.Count -gt 0) {
    Write-Host (" items in affected folders    : {0}" -f
        (($affected | Measure-Object ItemsInFolder -Sum).Sum))
    $oldest = $affected | Where-Object OldestItemReceivedDate |
              Sort-Object OldestItemReceivedDate | Select-Object -First 1
    if ($oldest) {
        Write-Host (" oldest item in scope         : {0}  ({1})" -f
            $oldest.OldestItemReceivedDate, $oldest.FolderPath)
    }
}
Write-Host (" CSV: {0}" -f $fsCsv) -ForegroundColor Cyan

# --- 2) Recoverable Items ----------------------------------------------------
if ($IncludeRecoverableItems) {
    if (-not (Get-Command Get-RecoverableItems -ErrorAction SilentlyContinue)) {
        throw 'Get-RecoverableItems not available - needs the Mailbox Import Export role.'
    }
    Write-Host ''
    Write-Host '=============== RECOVERABLE ITEMS ===============' -ForegroundColor Cyan

    $splat = @{ Identity = $Mailbox; SourceFolder = 'RecoverableItems'; ResultSize = $RecoverableItemsMax }
    if ($PolicyTag) {
        # EXO-only: filters deleted items by the retention tag that expired them.
        $splat.PolicyTag = $PolicyTag
        Write-Host (" filtered by PolicyTag {0}" -f $PolicyTag) -ForegroundColor Yellow
    }
    $ri = @(Get-RecoverableItems @splat)

    if ($ri.Count -eq 0) {
        Write-Host ' No recoverable items matched.' -ForegroundColor Green
    }
    else {
        $riCsv = Join-Path $OutputDirectory "exo-recoverableitems-${stamp}.csv"
        $ri | Select-Object Subject, ItemClass, LastParentPath, LastParentFolderID,
                            LastModifiedTime, SourceFolder, OriginalFolderExists, EntryID |
             Export-Csv -Path $riCsv -NoTypeInformation -Encoding utf8

        Write-Host (" items returned (cap {0}) : {1}" -f $RecoverableItemsMax, $ri.Count)
        Write-Host ''
        Write-Host ' by LastParentPath (where they came from):'
        $ri | Group-Object LastParentPath | Sort-Object Count -Descending |
            Select-Object -First 20 @{n='LastParentPath';e={ if ($_.Name) { $_.Name } else { '<unknown>' } }}, Count |
            Format-Table -AutoSize | Out-String -Width 200 | Write-Host

        Write-Host ' by item class:'
        $ri | Group-Object ItemClass | Sort-Object Count -Descending |
            Select-Object Name, Count | Format-Table -AutoSize | Out-String | Write-Host

        Write-Host ' deletion timeline (LastModifiedTime, per hour):'
        $ri | Where-Object LastModifiedTime |
            Group-Object { ([datetime]$_.LastModifiedTime).ToString('yyyy-MM-dd HH:00') } |
            Sort-Object Count -Descending | Select-Object -First 10 Name, Count |
            Format-Table -AutoSize | Out-String | Write-Host

        $noOrig = @($ri | Where-Object { -not $_.OriginalFolderExists })
        if ($noOrig.Count -gt 0) {
            Write-Host (" WARNING: {0} item(s) whose original folder no longer exists -" -f $noOrig.Count) -ForegroundColor Yellow
            Write-Host ' those cannot be restored to their original location.' -ForegroundColor Yellow
        }
        Write-Host (" CSV: {0}" -f $riCsv) -ForegroundColor Cyan
        Write-Host ''
        Write-Host ' Restore would be (NOT run by this script - restore is a human decision):' -ForegroundColor Cyan
        Write-Host ("   Restore-RecoverableItems -Identity {0} -SourceFolder RecoverableItems{1}" -f
            $Mailbox, $(if ($PolicyTag) { " -PolicyTag ${PolicyTag}" } else { '' })) -ForegroundColor Cyan
    }
}

Write-Host ''
Write-Host 'Get-MailboxFolderStatistics reports the EFFECTIVE policy; the EWS census reports' -ForegroundColor Cyan
Write-Host 'PHYSICAL stamps. A difference between the two is expected, not an error.'          -ForegroundColor Cyan
