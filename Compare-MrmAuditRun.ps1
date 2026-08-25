#Requires -Version 5.1
<#
.SYNOPSIS
Compares two audit runs - folder census and/or item audit - and reports what
actually changed between them. READ-ONLY, works purely on the evidence files.

.DESCRIPTION
Answers the questions you cannot answer by eyeballing 20.000 CSV rows:
  * which folders LOST the target tag, which GAINED it, which are unchanged
  * which items lost it, gained it, and which items VANISHED (deleted!)
  * whether RetentionDate moved

Matching is by ID (FolderId / ItemId), never by path or subject - paths are
display strings and a folder name may itself contain a slash.

Pass either the evidence directory (newest two runs are picked automatically)
or two explicit files.

.EXAMPLE
    ./Compare-MrmAuditRun.ps1 -EvidenceDirectory .\evidence
.EXAMPLE
    ./Compare-MrmAuditRun.ps1 -BeforeCsv .\evidence\folder-census-A.csv `
                              -AfterCsv  .\evidence\folder-census-B.csv
.EXAMPLE
    ./Compare-MrmAuditRun.ps1 -EvidenceDirectory .\evidence -Kind Items -ExportDelta
#>
[CmdletBinding(DefaultParameterSetName='Directory')]
param(
    [Parameter(Mandatory, ParameterSetName='Directory')][string]$EvidenceDirectory,
    [Parameter(ParameterSetName='Directory')][ValidateSet('Folders','Items','Both')][string]$Kind = 'Both',

    [Parameter(Mandatory, ParameterSetName='Explicit')][string]$BeforeCsv,
    [Parameter(Mandatory, ParameterSetName='Explicit')][string]$AfterCsv,

    [string]$TargetRetentionId = 'd94993b5-e987-4275-8707-072057cfb2b8',
    [switch]$ExportDelta
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$tgt = $TargetRetentionId.Trim().ToLowerInvariant()

function Get-NewestPair {
    param([string]$Dir, [string]$Pattern)
    $files = @(Get-ChildItem -Path $Dir -Filter $Pattern -File -ErrorAction SilentlyContinue |
               Sort-Object LastWriteTime -Descending)
    if ($files.Count -lt 2) { return $null }
    return [pscustomobject]@{ Before = $files[1]; After = $files[0] }   # [1] is older
}

function Compare-TagSets {
    <# Pure comparison keyed by an ID column. Returns the four buckets that
       matter: lost the tag, gained it, still tagged, and GONE (present before,
       absent after - for items that means deleted). #>
    param(
        [Parameter(Mandatory)][object[]]$Before,
        [Parameter(Mandatory)][object[]]$After,
        [Parameter(Mandatory)][string]$KeyProperty,
        [Parameter(Mandatory)][string]$Target
    )
    $b = @{}; foreach ($x in $Before) { if ($x.$KeyProperty) { $b[$x.$KeyProperty] = $x } }
    $a = @{}; foreach ($x in $After)  { if ($x.$KeyProperty) { $a[$x.$KeyProperty] = $x } }

    $lost = [System.Collections.Generic.List[object]]::new()
    $kept = [System.Collections.Generic.List[object]]::new()
    $gone = [System.Collections.Generic.List[object]]::new()
    $gained = [System.Collections.Generic.List[object]]::new()

    foreach ($k in $b.Keys) {
        $wasTagged = ($b[$k].PolicyTagRetentionId -eq $Target)
        if (-not $a.ContainsKey($k)) {
            if ($wasTagged) { $gone.Add($b[$k]) }
            continue
        }
        $isTagged = ($a[$k].PolicyTagRetentionId -eq $Target)
        if     ($wasTagged -and -not $isTagged) { $lost.Add($b[$k]) }
        elseif ($wasTagged -and $isTagged)      { $kept.Add($b[$k]) }
    }
    foreach ($k in $a.Keys) {
        if (-not $b.ContainsKey($k)) { continue }
        if (($a[$k].PolicyTagRetentionId -eq $Target) -and ($b[$k].PolicyTagRetentionId -ne $Target)) {
            $gained.Add($a[$k])
        }
    }
    return [pscustomobject]@{
        BeforeCount = @($Before).Count; AfterCount = @($After).Count
        BeforeTagged = @($Before | Where-Object { $_.PolicyTagRetentionId -eq $Target }).Count
        AfterTagged  = @($After  | Where-Object { $_.PolicyTagRetentionId -eq $Target }).Count
        Lost = $lost; Kept = $kept; Gained = $gained; Gone = $gone
    }
}

function Show-Comparison {
    param([string]$Label, $Result, [string]$KeyProperty, $BeforeFile, $AfterFile)
    Write-Host ''
    Write-Host "=============== ${Label} ===============" -ForegroundColor Cyan
    Write-Host ("  before : {0}  ({1})" -f (Split-Path $BeforeFile -Leaf), $BeforeFile.LastWriteTime)
    Write-Host ("  after  : {0}  ({1})" -f (Split-Path $AfterFile  -Leaf), $AfterFile.LastWriteTime)
    Write-Host ''
    Write-Host ("  rows            : {0}  ->  {1}" -f $Result.BeforeCount, $Result.AfterCount)
    Write-Host ("  carrying target : {0}  ->  {1}" -f $Result.BeforeTagged, $Result.AfterTagged)
    Write-Host ''
    Write-Host ("  LOST the tag (repaired) : {0}" -f $Result.Lost.Count)   -ForegroundColor Green
    Write-Host ("  still tagged            : {0}" -f $Result.Kept.Count)
    Write-Host ("  GAINED the tag (!)      : {0}" -f $Result.Gained.Count) -ForegroundColor $(if ($Result.Gained.Count) { 'Red' } else { 'Gray' })
    Write-Host ("  VANISHED (gone!)        : {0}" -f $Result.Gone.Count)   -ForegroundColor $(if ($Result.Gone.Count) { 'Red' } else { 'Gray' })

    if ($Result.Lost.Count -gt 0) {
        Write-Host ''
        Write-Host '  first repaired entries:'
        $Result.Lost | Select-Object -First 10 | ForEach-Object {
            Write-Host ("    {0}" -f $(if ($_.PSObject.Properties['FolderPath']) { $_.FolderPath } else { $_.$KeyProperty }))
        }
    }
    if ($Result.Gone.Count -gt 0) {
        Write-Host ''
        Write-Host '  VANISHED entries - these existed before and are absent now:' -ForegroundColor Red
        $Result.Gone | Select-Object -First 10 | ForEach-Object {
            Write-Host ("    {0}" -f $(if ($_.PSObject.Properties['FolderPath']) { $_.FolderPath } else { $_.$KeyProperty })) -ForegroundColor Red
        }
        Write-Host '  For ITEMS this means deleted. Check whether MFA ran.' -ForegroundColor Red
    }
    if ($Result.Gained.Count -gt 0) {
        Write-Host ''
        Write-Host '  GAINED the tag - something re-applied it:' -ForegroundColor Red
        $Result.Gained | Select-Object -First 10 | ForEach-Object {
            Write-Host ("    {0}" -f $(if ($_.PSObject.Properties['FolderPath']) { $_.FolderPath } else { $_.$KeyProperty })) -ForegroundColor Red
        }
    }
}

$pairs = @()
if ($PSCmdlet.ParameterSetName -eq 'Explicit') {
    $pairs += [pscustomobject]@{ Label='CUSTOM'; Key='FolderId'
                                 Before=(Get-Item $BeforeCsv); After=(Get-Item $AfterCsv) }
}
else {
    if ($Kind -in @('Folders','Both')) {
        foreach ($pat in @('folder-census-*.csv','pre-repair-census-*.csv')) {
            $p = Get-NewestPair -Dir $EvidenceDirectory -Pattern $pat
            if ($p) { $pairs += [pscustomobject]@{ Label="FOLDERS (${pat})"; Key='FolderId'; Before=$p.Before; After=$p.After } }
        }
    }
    if ($Kind -in @('Items','Both')) {
        $p = Get-NewestPair -Dir $EvidenceDirectory -Pattern 'item-audit-*.csv'
        if ($p) { $pairs += [pscustomobject]@{ Label='ITEMS'; Key='ItemId'; Before=$p.Before; After=$p.After } }
    }
    if (-not $pairs) { throw "Need at least two runs of the same kind in ${EvidenceDirectory}." }
}

foreach ($pair in $pairs) {
    $before = @(Import-Csv -Path $pair.Before.FullName)
    $after  = @(Import-Csv -Path $pair.After.FullName)
    $res = Compare-TagSets -Before $before -After $after -KeyProperty $pair.Key -Target $tgt
    Show-Comparison -Label $pair.Label -Result $res -KeyProperty $pair.Key `
                    -BeforeFile $pair.Before -AfterFile $pair.After

    if ($ExportDelta) {
        $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
        $base  = Join-Path (Split-Path $pair.After.FullName -Parent) ("delta-{0}-{1}" -f ($pair.Label -replace '[^A-Za-z]',''), $stamp)
        foreach ($bucket in 'Lost','Gained','Gone','Kept') {
            if ($res.$bucket.Count -gt 0) {
                $res.$bucket | Export-Csv -Path "${base}-${bucket}.csv" -NoTypeInformation -Encoding utf8
            }
        }
        Write-Host ''
        Write-Host ("  delta CSVs: {0}-*.csv" -f $base) -ForegroundColor Cyan
    }
}

Write-Host ''
Write-Host 'Matching is by ID (FolderId / ItemId), never by path or subject.' -ForegroundColor Cyan
