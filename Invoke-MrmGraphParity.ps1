#Requires -Version 5.1
<#
.SYNOPSIS
    PHASE 2 — Microsoft Graph parity.

    2A (default): read-only Graph census of the same mailbox reading
        Binary 0x3019 / Integer 0x301A / Integer 0x301D / Binary 0x3018
        as singleValueLegacyExtendedProperties, compared against the latest
        EWS census JSON. EWS is the oracle.

    2B (gated): -ExperimentalWriteProbe on exactly ONE named disposable
        folder. Refuses without -IUnderstandThisIsAnExperiment. Until the
        probe result is EWS-confirmed identical to the fixture contract,
        the project position is:
            READ/AUDIT parity  : supported
            WRITE/UNTAG parity : NOT PROVEN — mutation stays EWS-only.

    Graph permission: application Mail.ReadWrite (admin consented).
    v1.0 only; no beta endpoints are used.
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact='High', DefaultParameterSetName='Certificate')]
param(
    [Parameter(Mandatory)][string]$TenantId,
    [Parameter(Mandatory)][string]$ClientId,
    [Parameter(Mandatory, ParameterSetName='Certificate')][string]$CertificateThumbprint,
    [Parameter(ParameterSetName='Certificate')][string]$CertificateStore = 'Cert:\CurrentUser\My',
    [Parameter(Mandatory, ParameterSetName='Secret')][securestring]$ClientSecret,
    [Parameter(Mandatory)][string]$Mailbox,
    [Parameter(Mandatory)][string]$TargetRetentionId,
    [Parameter(Mandatory)][string]$EwsCensusJson,      # folder-census-*.json from Phase 1A
    [switch]$IncludeHidden,
    [switch]$ExperimentalWriteProbe,
    [string]$ProbeGraphFolderId,                        # ONE disposable test folder
    [switch]$IUnderstandThisIsAnExperiment,
    [string]$OutputDirectory = (Join-Path $PSScriptRoot 'evidence')
)

Import-Module (Join-Path $PSScriptRoot 'MRM-RetentionRepair.psm1') -Force
New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
$tgt = Test-MrmTargetRetentionId -TargetRetentionId $TargetRetentionId

# Token provider closure (Graph scope) — supports -Force refresh on 401.
if ($PSCmdlet.ParameterSetName -eq 'Certificate') {
    $cert = Get-ChildItem $CertificateStore | Where-Object Thumbprint -eq $CertificateThumbprint
    if (-not $cert) { throw "Certificate ${CertificateThumbprint} not found in ${CertificateStore}." }
    $tokenProvider = { param([switch]$Force)
        Get-MrmAccessToken -TenantId $TenantId -ClientId $ClientId -Certificate $cert `
            -Scope 'https://graph.microsoft.com/.default' -Force:$Force }.GetNewClosure()
} else {
    $tokenProvider = { param([switch]$Force)
        Get-MrmAccessToken -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret `
            -Scope 'https://graph.microsoft.com/.default' -Force:$Force }.GetNewClosure()
}

# --- 2A read parity ----------------------------------------------------------
$ewsCensus = Get-Content $EwsCensusJson -Raw | ConvertFrom-Json
$graphCensus = Get-MrmGraphFolderCensus -Mailbox $Mailbox -TokenProvider $tokenProvider -IncludeHidden:$IncludeHidden
Export-MrmEvidence -Records $graphCensus -OutputDirectory $OutputDirectory -BaseName 'graph-census' | Out-Null

$parity = Compare-MrmCensusParity -EwsCensus $ewsCensus -GraphCensus $graphCensus -TargetRetentionId $tgt
$parity | ConvertTo-Json -Depth 6 | Set-Content (Join-Path $OutputDirectory 'graph-parity-report.json') -Encoding utf8

Write-Host ''
Write-Host '=============================================================='
Write-Host ' GRAPH READ PARITY (EWS is the oracle)'
Write-Host '--------------------------------------------------------------'
Write-Host " EWS physical target folders:   $($parity.EwsPhysicalTargetFolders)"
Write-Host " Graph physical target folders: $($parity.GraphPhysicalTargetFolders)"
Write-Host " Matched:                       $($parity.Matched)"
Write-Host " Missing in Graph:              $($parity.MissingInGraph)"
Write-Host " Extra in Graph:                $($parity.ExtraInGraph)"
Write-Host " Property mismatches:           $($parity.PropertyMismatches)"
Write-Host " Parity OK:                     $($parity.ParityOk)"
Write-Host '=============================================================='
if (-not $parity.ParityOk) {
    Write-MrmLog -Level Warning -Message 'Gate 7 NOT passed — Graph mutation remains forbidden until read parity is understood.'
}
else {
    Write-MrmLog -Level Info -Message 'Gate 7 passed: Graph read parity established.'
}

# --- 2B write probe (gated) --------------------------------------------------
if ($ExperimentalWriteProbe) {
    if (-not $parity.ParityOk) { throw 'REFUSED: read parity (Gate 7) must pass before any write experiment (Gate 8).' }
    if (-not $ProbeGraphFolderId) { throw 'REFUSED: -ProbeGraphFolderId (ONE disposable test folder) is mandatory for the write probe.' }
    $probe = Invoke-MrmGraphWriteProbe -Mailbox $Mailbox -GraphFolderId $ProbeGraphFolderId `
                -TokenProvider $tokenProvider -IUnderstandThisIsAnExperiment:$IUnderstandThisIsAnExperiment
    $probe | ConvertTo-Json -Depth 8 | Set-Content (Join-Path $OutputDirectory 'graph-write-probe.json') -Encoding utf8
    Write-Host ''
    Write-Host ' WRITE PROBE captured to graph-write-probe.json.'
    Write-Host ' NOT PROVEN until: EWS re-read of the same folder matches'
    Write-Host ' tests/fixtures/ews-policytag-null-after.json exactly.'
    Write-Host ' Until then: WRITE/UNTAG parity = unsupported, mutation stays EWS-only.'
}
else {
    Write-Host ''
    Write-Host ' Current project position:'
    Write-Host '   READ/AUDIT parity  : ' -NoNewline; Write-Host $(if ($parity.ParityOk) { 'supported' } else { 'not yet' })
    Write-Host '   WRITE/UNTAG parity : not proven — EWS remains required for mutation.'
}
