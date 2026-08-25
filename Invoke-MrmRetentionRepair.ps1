#Requires -Version 5.1
<#
.SYNOPSIS
    PHASE 1C — surgical EWS folder untag. DRY-RUN BY DEFAULT.

    Removes the physical PolicyTag ONLY from folders whose live physical
    RetentionId equals -TargetRetentionId, using the native EWS semantic
    (PolicyTag = $null; Update()). Everything else is untouched:
    other personal tags, "Never Delete", ArchiveTag, tenant policy, MFA state.

    Recommended live sequence (Gate 5 before Gate 6):
      1. Dry run (no -Apply) — review the candidate list.
      2. Pilot on ONE controlled folder:
           -Apply -PilotFolderPath '/Archive/Projects/<one branch>' -CaptureFixture
         Then verify externally (Get-MailboxFolderStatistics -IncludeAnalysis)
         and inspect the before/after fixtures.
      3. Only after operator review: full -Apply.

    This script NEVER calls Start-ManagedFolderAssistant, never changes
    ElcProcessingDisabled, never touches tenant tags/policies.

.EXAMPLE
    # Dry run
    ./Invoke-MrmRetentionRepair.ps1 -TenantId <tid> -ClientId <appid> `
        -CertificateThumbprint <thumb> -Mailbox user@contoso.com `
        -TargetRetentionId d94993b5-e987-4275-8707-072057cfb2b8

.EXAMPLE
    # Gate 5: controlled single-folder pilot with fixture capture
    ./Invoke-MrmRetentionRepair.ps1 ... -Apply `
        -PilotFolderPath '/Archive/Projects/ProjectB' -CaptureFixture
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact='High', DefaultParameterSetName='Certificate')]
param(
    [Parameter(Mandatory)][string]$TenantId,
    [Parameter(Mandatory)][string]$ClientId,
    [Parameter(Mandatory, ParameterSetName='Certificate')][string]$CertificateThumbprint,
    [Parameter(ParameterSetName='Certificate')][string]$CertificateStore = 'Cert:\CurrentUser\My',
    [Parameter(Mandatory, ParameterSetName='CertificateFile')][string]$CertificatePath,
    [Parameter(ParameterSetName='CertificateFile')][securestring]$CertificatePassword,
    [Parameter(Mandatory, ParameterSetName='Secret')][securestring]$ClientSecret,
    [Parameter(Mandatory)][string]$Mailbox,
    [Parameter(Mandatory)][string]$TargetRetentionId,
    [switch]$Apply,
    [string]$PilotFolderPath,          # restrict Apply to exactly one folder path (Gate 5)
    [switch]$CaptureFixture,           # persist redacted before/after fixtures for the Graph oracle
    [string]$OutputDirectory = (Join-Path $PSScriptRoot 'evidence')
)

Import-Module (Join-Path $PSScriptRoot 'MRM-RetentionRepair.psm1') -Force
$log = Join-Path $OutputDirectory ("repair-{0:yyyyMMdd-HHmmss}.log" -f (Get-Date))
New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null

$tgt = Test-MrmTargetRetentionId -TargetRetentionId $TargetRetentionId   # throws on protected/invalid

switch ($PSCmdlet.ParameterSetName) {
    'Certificate' {
        $cert = Get-ChildItem $CertificateStore | Where-Object Thumbprint -eq $CertificateThumbprint
        if (-not $cert) { throw "Certificate ${CertificateThumbprint} not found in ${CertificateStore}." }
        $token = Get-MrmAccessToken -TenantId $TenantId -ClientId $ClientId -Certificate $cert
    }
    'CertificateFile' {
        $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
            $CertificatePath,
            $(if ($CertificatePassword) { [System.Net.NetworkCredential]::new('', $CertificatePassword).Password } else { '' }),
            [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::EphemeralKeySet)
        $token = Get-MrmAccessToken -TenantId $TenantId -ClientId $ClientId -Certificate $cert
    }
    'Secret' {
        Write-MrmLog -LogPath $log -Level Warning -Message 'Client-secret auth in use — certificate auth is preferred.'
        $token = Get-MrmAccessToken -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret
    }
}

$service = Connect-MrmEwsService -Mailbox $Mailbox -AccessToken $token

# ALWAYS take a fresh census + evidence snapshot before any write.
$census = Get-MrmFolderCensus -Service $service
Export-MrmEvidence -Records $census -OutputDirectory $OutputDirectory -BaseName 'pre-repair-census' | Out-Null

$scope = $census
if ($PilotFolderPath) {
    $scope = @($census | Where-Object FolderPath -eq $PilotFolderPath)
    if (-not $scope) { throw "PilotFolderPath '${PilotFolderPath}' not found in census." }
    Write-MrmLog -LogPath $log -Level Info -Message "PILOT MODE: scope restricted to exactly '${PilotFolderPath}'."
}

$candidates = @($scope | Where-Object { $_.HasPhysicalPolicyTag -and $_.PolicyTagRetentionId -eq $tgt })

Write-Host ''
Write-Host '=============================================================='
if ($Apply) { Write-Host ' MODE: APPLY' -ForegroundColor Magenta } else { Write-Host ' MODE: AUDIT ONLY (dry run — add -Apply to mutate)' }
Write-Host "--------------------------------------------------------------"
Write-Host " Target RetentionId:        ${tgt}"
Write-Host " Matched physical folders:  $($candidates.Count)"
Write-Host ''
Write-Host ' Will NOT modify:'
Write-Host '   - other Personal tags'
Write-Host '   - Never Delete (414c6a14-3ed5-432e-9edb-c6620a8278f0)'
Write-Host '   - ArchiveTag'
Write-Host '   - tenant retention policy / MRM tags'
Write-Host '   - MFA / ElcProcessingDisabled state'
Write-Host '=============================================================='
$candidates | Select-Object FolderPath, PolicyTagRetentionId, RetentionPeriod, RetentionFlagsDecoded, ItemCount |
    Format-Table -AutoSize | Out-String | Write-Host

$result = Invoke-MrmFolderUntag -Service $service -Census $scope -TargetRetentionId $tgt `
            -Apply:$Apply -SnapshotDirectory $OutputDirectory -LogPath $log `
            -WhatIf:$WhatIfPreference -Confirm:$false

if ($Apply -and $result.Changed.Count -gt 0) {
    # Post-change verification pass + child inheritance check
    foreach ($chg in $result.Changed) {
        $child = @($census | Where-Object ParentFolderId -eq $chg.FolderId | Select-Object -First 1)
        if ($child) {
            $childAfter = Get-MrmFolderRawState -Service $service -FolderId $child[0].FolderId
            Write-MrmLog -LogPath $log -Level Info -Message "Child inheritance check '$($childAfter.FolderPath)': physical=$($childAfter.HasPhysicalPolicyTag) tag=$($childAfter.PolicyTagRetentionId) flags=$($childAfter.RetentionFlagsDecoded). Effective view must be compared externally via Get-MailboxFolderStatistics -IncludeAnalysis."
        }
    }

    if ($CaptureFixture) {
        $fixDir = Join-Path $PSScriptRoot 'tests/fixtures'
        New-Item -ItemType Directory -Force -Path $fixDir | Out-Null
        $first = $result.Changed[0]
        # Redact mailbox-identifying material before persisting as committable fixture.
        $redact = {
            param($state)
            $c = $state | ConvertTo-Json -Depth 6 | ConvertFrom-Json
            $c.FolderPath  = '/REDACTED' + ($c.FolderPath -replace '^.*/', '/')
            $c.DisplayName = 'REDACTED'
            $c.FolderId    = 'REDACTED-EWSID'
            if ($c.PSObject.Properties['ParentFolderId']) { $c.ParentFolderId = 'REDACTED' }
            $c
        }
        (& $redact $first.Before) | ConvertTo-Json -Depth 6 | Set-Content (Join-Path $fixDir 'ews-policytag-null-before.json') -Encoding utf8
        (& $redact $first.After)  | ConvertTo-Json -Depth 6 | Set-Content (Join-Path $fixDir 'ews-policytag-null-after.json')  -Encoding utf8
        Write-MrmLog -LogPath $log -Level Info -Message 'Gate 5 fixtures captured (redacted): tests/fixtures/ews-policytag-null-{before,after}.json — these are the Graph oracle contract.'
    }

    Write-Host ''
    Write-Host ' NEXT (manual, outside this tool):'
    Write-Host '   Get-MailboxFolderStatistics <mbx> -IncludeAnalysis | compare DeletePolicy/RetentionFlags'
    Write-Host '   Do NOT run Start-ManagedFolderAssistant — operator decision only, after restore.'
}

Write-Host ''
Write-Host "Change log / evidence: ${OutputDirectory}"
