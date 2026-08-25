#Requires -Version 5.1
<#
.SYNOPSIS
    PHASE 1A/1B - READ-ONLY audit. Never mutates anything.

    1A: deep physical-tag census + Exists(PR_POLICY_TAG) cross-check + the
        falsifier (16 vs 261 vs C - prints the ACTUAL result).
    1B: bounded item-level physical-tag audit of the affected folders
        (opt-in via -IncludeItemAudit).

.EXAMPLE
    ./Invoke-MrmRetentionAudit.ps1 -TenantId <tid> -ClientId <appid> `
        -CertificateThumbprint <thumb> -Mailbox user@contoso.com `
        -TargetRetentionId d94993b5-e987-4275-8707-072057cfb2b8 `
        -KnownEffectiveCount 261 -IncludeItemAudit -OutputDirectory ./evidence
#>
[CmdletBinding(DefaultParameterSetName='Certificate')]
param(
    [Parameter(Mandatory, ParameterSetName='Certificate')][Parameter(Mandatory, ParameterSetName='CertificateFile')][Parameter(Mandatory, ParameterSetName='Secret')]
    [Parameter(ParameterSetName='Config')][string]$TenantId,
    [Parameter(Mandatory, ParameterSetName='Certificate')][Parameter(Mandatory, ParameterSetName='CertificateFile')][Parameter(Mandatory, ParameterSetName='Secret')]
    [Parameter(ParameterSetName='Config')][string]$ClientId,
    [Parameter(Mandatory, ParameterSetName='Certificate')][string]$CertificateThumbprint,
    [Parameter(ParameterSetName='Certificate')][string]$CertificateStore = 'Cert:\CurrentUser\My',
    [Parameter(Mandatory, ParameterSetName='CertificateFile')][string]$CertificatePath,
    [Parameter(ParameterSetName='CertificateFile')][securestring]$CertificatePassword,
    [Parameter(Mandatory, ParameterSetName='Secret')][securestring]$ClientSecret,
    [Parameter(Mandatory, ParameterSetName='Config')][string]$ConfigPath,
    [Parameter(Mandatory, ParameterSetName='Certificate')][Parameter(Mandatory, ParameterSetName='CertificateFile')][Parameter(Mandatory, ParameterSetName='Secret')]
    [Parameter(ParameterSetName='Config')][string]$Mailbox,
    [Parameter(Mandatory, ParameterSetName='Certificate')][Parameter(Mandatory, ParameterSetName='CertificateFile')][Parameter(Mandatory, ParameterSetName='Secret')]
    [Parameter(ParameterSetName='Config')][string]$TargetRetentionId,
    [Nullable[int]]$KnownEffectiveCount,       # e.g. 261 from external Get-MailboxFolderStatistics
    [switch]$IncludeItemAudit,
    [int]$MaxItemsPerFolder = 2000,
    [switch]$IncludeSubjects,                   # off by default - audit stays content-minimal
    [string]$OutputDirectory = (Join-Path $PSScriptRoot 'evidence')
)

Import-Module (Join-Path $PSScriptRoot 'MRM-RetentionRepair.psm1') -Force
$log = Join-Path $OutputDirectory ("audit-{0:yyyyMMdd-HHmmss}.log" -f (Get-Date))
New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null

# --- token -------------------------------------------------------------------

# --- Config mode: JSON settings, CLI overrides config, config overrides defaults
$authMode = $PSCmdlet.ParameterSetName
if ($authMode -eq 'Config') {
    $cfg = Get-MrmConfig -Path $ConfigPath
    foreach ($n in @('TenantId','ClientId','Mailbox','TargetRetentionId','KnownEffectiveCount','MaxItemsPerFolder','OutputDirectory','CertificateThumbprint','CertificateStore','CertificatePath')) {
        if (-not $PSBoundParameters.ContainsKey($n) -and $cfg.PSObject.Properties[$n] -and
            $null -ne $cfg.$n -and '' -ne [string]$cfg.$n) {
            Set-Variable -Name $n -Value $cfg.$n -WhatIf:$false -Confirm:$false
        }
    }
    if (-not $ClientSecret        -and $cfg.PSObject.Properties['ClientSecret']        -and $cfg.ClientSecret)        { $ClientSecret        = $cfg.ClientSecret }
    if (-not $CertificatePassword -and $cfg.PSObject.Properties['CertificatePassword'] -and $cfg.CertificatePassword) { $CertificatePassword = $cfg.CertificatePassword }
    foreach ($req in @('TenantId','ClientId','Mailbox','TargetRetentionId')) {
        if (-not (Get-Variable -Name $req -ValueOnly)) { throw "Config/CLI is missing required setting: ${req} (${ConfigPath})" }
    }
    $authMode = if ($CertificateThumbprint) { 'Certificate' }
                elseif ($CertificatePath)   { 'CertificateFile' }
                elseif ($ClientSecret)      { 'Secret' }
                else { throw "Config ${ConfigPath} provides no authentication material (CertificateThumbprint / CertificatePath / ClientSecretEncrypted)." }
    Write-MrmLog -Level Info -Message "Config loaded: ${ConfigPath} (auth mode: ${authMode}; secrets never logged)."
}
switch ($authMode) {
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
        Write-MrmLog -LogPath $log -Level Warning -Message 'Client-secret auth in use - certificate auth is preferred.'
        $token = Get-MrmAccessToken -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret
    }
}

$service = Connect-MrmEwsService -Mailbox $Mailbox -AccessToken $token
Write-MrmLog -LogPath $log -Level Info -Message "Gate 1 passed: EWS OAuth connection prepared for ${Mailbox} (explicit endpoint, no Autodiscover)."

# --- Phase 1A census ---------------------------------------------------------
$census = @(Get-MrmFolderCensus -Service $service)
# A census of zero folders means the connection failed, not that the mailbox is
# clean. Never let a broken run look like an all-clear.
if ($census.Count -eq 0) {
    throw ("Census returned 0 folders for ${Mailbox}. That is not a clean mailbox - " +
           "it means the EWS call did not succeed (auth, impersonation/ApplicationAccessPolicy, " +
           "or assembly load). Refusing to report an all-clear.")
}
$snap = Export-MrmEvidence -Records $census -OutputDirectory $OutputDirectory -BaseName 'folder-census'
Write-MrmLog -LogPath $log -Level Info -Message "Gate 2 passed: physical-tag census complete ($($census.Count) folders). Evidence: $($snap -join ', ')"

$summary = Get-MrmCensusSummary -Census $census -TargetRetentionId $TargetRetentionId -KnownEffectiveCount $KnownEffectiveCount
$summary | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $OutputDirectory 'census-summary.json') -Encoding utf8

$mask = $Mailbox -replace '(?<=^.).+(?=.@)', '***'
Write-Host ''
Write-Host '=============================================================='
Write-Host " Mailbox:            ${mask}"
Write-Host " Target RetentionId: $($summary.TargetRetentionId)"
Write-Host '--------------------------------------------------------------'
Write-Host " Folders scanned:              $($summary.FoldersScanned)"
Write-Host " Physical PR_POLICY_TAG:       $($summary.PhysicalPolicyTagFolders)"
Write-Host " Exists() cross-check:         $($summary.ExistsFilterFolders)"
Write-Host " Physical TARGET tags:         $($summary.PhysicalTargetTagFolders)"
Write-Host " Effective target (external):  $($summary.KnownEffectiveTargetFolders)"
Write-Host " Other physical policy tags:   $($summary.PhysicalOtherPolicyTags)"
Write-Host '--------------------------------------------------------------'
Write-Host " FALSIFIER: $($summary.Conclusion)"
Write-Host '--------------------------------------------------------------'
Write-Host ' MODE: AUDIT ONLY - NO CHANGES MADE'
Write-Host '=============================================================='
Write-MrmLog -LogPath $log -Level Info -Message "Gate 3 evidence: $($summary.Conclusion)"

# --- Phase 1B item audit -----------------------------------------------------
if ($IncludeItemAudit) {
    $tgt = Test-MrmTargetRetentionId -TargetRetentionId $TargetRetentionId
    $affected = @($census | Where-Object { $_.PolicyTagRetentionId -eq $tgt })
    if (-not $affected) {
        # No physical stamps - audit items of every folder branch the operator flags is
        # out of scope here; sample the whole tree bounded instead.
        Write-MrmLog -LogPath $log -Level Warning -Message 'No physically target-stamped folders; item audit will sample ALL folders with items (bounded).'
        $affected = @($census | Where-Object { $_.ItemCount -gt 0 })
    }
    $items = $null
    $itemAuditError = $null
    try {
        $items = @(Get-MrmItemAudit -Service $service -Folders $affected -MaxItemsPerFolder $MaxItemsPerFolder -IncludeSubjects:$IncludeSubjects)
    }
    catch {
        $itemAuditError = $_.Exception.Message
        Write-MrmLog -LogPath $log -Level Error -Message "Gate 4 FAILED: item audit did not complete - $itemAuditError"
    }
    if ($itemAuditError) {
        Write-Host ''
        Write-Host ' Item-level physical audit: FAILED - NO CONCLUSION POSSIBLE' -ForegroundColor Red
        Write-Host "   $itemAuditError" -ForegroundColor Red
        Write-Host '   Do NOT read this as "no item stamps". Re-run the item audit before'  -ForegroundColor Red
        Write-Host '   making any decision about restored items.' -ForegroundColor Red
        Write-Host ''
        Write-Host "Evidence directory: ${OutputDirectory}"
        return
    }
    if ($items) { Export-MrmEvidence -Records $items -OutputDirectory $OutputDirectory -BaseName 'item-audit' | Out-Null }

    # FindItems is not guaranteed to return every requested extended property.
    # Bind a small sample and compare before drawing ANY conclusion from a
    # missing 0x301A/0x301D.
    $fidelity = @()
    try { $fidelity = @(Test-MrmItemPropertyFidelity -Service $service -Items $items -SampleSize 5) }
    catch { Write-MrmLog -LogPath $log -Level Warning -Message "Property fidelity check failed: $($_.Exception.Message)" }
    if ($fidelity) {
        Write-Host ''
        Write-Host ' Property fidelity (FindItems vs. direct Bind, 5 sampled items):'
        $fidelity | Format-Table FolderPath, Bind_Policy, FindItems_Period, Bind_Period,
                                 FindItems_FlagsRaw, Bind_FlagsRaw, Bind_FlagsDecoded,
                                 Bind_RetentionDate, PropsAgree -AutoSize |
            Out-String -Width 220 | Write-Host
        $disagree = @($fidelity | Where-Object { -not $_.PropsAgree })
        if ($disagree.Count -gt 0) {
            Write-Host '   => FindItems did NOT return all properties. The item-audit CSV understates' -ForegroundColor Yellow
            Write-Host '      flags/period; trust the Bind column above.' -ForegroundColor Yellow
        } else {
            Write-Host '   => Bind confirms FindItems: the values really are what the CSV shows.' -ForegroundColor Green
        }
        $rd = @($fidelity | Where-Object { $_.Bind_RetentionDate })
        if ($rd) {
            Write-Host ''
            Write-Host ' PidTagRetentionDate (0x301C) = the date MFA would delete the item:'
            $rd | ForEach-Object { Write-Host ("   {0}  {1}" -f $_.Bind_RetentionDate, $_.FolderPath) }
        } else {
            Write-Host '   No RetentionDate (0x301C) on the sampled items.' -ForegroundColor Yellow
        }
    }

    $itemTarget = @($items | Where-Object { $_.PolicyTagRetentionId -eq $tgt })
    $dist = $items | Group-Object PolicyTagRetentionId | Sort-Object Count -Descending |
            Select-Object @{n='RetentionId';e={$_.Name}}, Count
    Write-Host ''
    Write-Host " Item-level physical audit (bounded, cap ${MaxItemsPerFolder}/folder):"
    Write-Host "   Items physically stamped (any tag): $($items.Count)"
    Write-Host "   Items physically TARGET-stamped:    $($itemTarget.Count)"
    $dist | Format-Table -AutoSize | Out-String | Write-Host
    if ($itemTarget.Count -gt 0) {
        Write-Host '   => Restored/current items DO carry physical stamps. Folder untag alone'
        Write-Host '      will NOT strip these - a separate, evidence-gated item-repair decision'
        Write-Host '      is required (NOT implemented as an automatic path by design).'
    } else {
        Write-Host '   => No physical item stamps found in the sample; item retention appears'
        Write-Host '      inherited/effective via the folder only.'
    }
    Write-MrmLog -LogPath $log -Level Info -Message "Gate 4 evidence: item-level physical stamps sampled=$($items.Count), target=$($itemTarget.Count)."
}

Write-Host ''
Write-Host "Evidence directory: ${OutputDirectory}"
