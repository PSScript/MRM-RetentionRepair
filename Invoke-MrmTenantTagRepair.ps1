#Requires -Version 5.1
<#
.SYNOPSIS
Tenant-scale removal of ONE physical MRM PolicyTag across many mailboxes -
with a deliberately slow learning curve:

    DryRun (default)  ->  -TestRun (tiny, capped pilot)  ->  -Apply (full)

Every single mutation runs the full evidence cell, per folder:

    READ (live re-read)  ->  BACKUP (JSONL before-snapshot)
    ->  SET (native EWS PolicyTag = $null)  ->  READ (after)
    ->  COMPARE (Verified: 0x3019 gone, first-class PolicyTag null)

An unexpected post-write state stops the affected mailbox immediately.

.DESCRIPTION
Mailbox selection - two modes:
  1) explicit users:  -Mailbox 'a@contoso.com'
                      -Mailbox 'a@contoso.com,b@contoso.com'      (comma/semicolon in one string)
                      -Mailbox @('a@contoso.com','b@contoso.com')  (real array)
                      any mix of the above; plus -MailboxCsv
  2) ALL user mailboxes: -AllMailboxes (raw Graph REST discovery, no Mg module;
                         needs Graph application permission User.Read.All)

Run modes (mutually exclusive; DryRun when neither is given):
  DryRun   - census + candidate list per mailbox, ZERO writes.
  -TestRun - gather experience first: writes, but capped to
             -TestRunMailboxLimit mailboxes (default 1) and
             -TestRunFolderLimit folders per mailbox (default 1).
  -Apply   - full run over all selected mailboxes.

.EXAMPLE
    # 1) dry run over two users
    ./Invoke-MrmTenantTagRepair.ps1 -ConfigPath ./configs/TENANT-A.json `
        -Mailbox 'a@contoso.com,b@contoso.com' -TargetRetentionId d94993b5-e987-4275-8707-072057cfb2b8

    # 2) first experience: ONE folder in ONE mailbox, full evidence cell
    ./Invoke-MrmTenantTagRepair.ps1 -ConfigPath ./configs/TENANT-A.json `
        -Mailbox 'a@contoso.com,b@contoso.com' -TargetRetentionId d94993b5-... -TestRun

    # 3) the real thing, all user mailboxes
    ./Invoke-MrmTenantTagRepair.ps1 -ConfigPath ./configs/TENANT-A.json `
        -AllMailboxes -TargetRetentionId d94993b5-... -Apply
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact='High', DefaultParameterSetName='Certificate')]
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

    [Parameter(ParameterSetName='Certificate')][Parameter(ParameterSetName='CertificateFile')][Parameter(ParameterSetName='Secret')]
    [Parameter(ParameterSetName='Config')][string]$TargetRetentionId,

    # ---- mailbox selection: mode 1 (explicit) / mode 2 (-AllMailboxes) ----
    [string[]]$Mailbox,           # 'a@c.com' | 'a@c.com,b@c.com' | @('a@c.com','b@c.com') | mixed
    [string]$MailboxCsv,
    [switch]$AllMailboxes,        # raw Graph REST discovery (User.Read.All), no Mg module
    [switch]$IncludeDisabled,

    # ---- run modes ----
    [switch]$TestRun,
    [int]$TestRunMailboxLimit = 1,
    [int]$TestRunFolderLimit  = 1,
    [switch]$Apply,

    [int]$ThrottleDelayMs = 500,
    [string]$OutputDirectory = (Join-Path $PSScriptRoot 'evidence\tenant-repair')
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Mode validation FIRST - before any auth or config work.
if ($TestRun -and $Apply) { throw 'PARAMETER ERROR: -TestRun and -Apply are mutually exclusive. DryRun -> -TestRun -> -Apply, in that order.' }
$runMode = if ($Apply) { 'Apply' } elseif ($TestRun) { 'TestRun' } else { 'DryRun' }

Import-Module (Join-Path $PSScriptRoot 'MRM-RetentionRepair.psm1') -Force

# --- Config mode: JSON settings, CLI overrides config ------------------------
$authMode = $PSCmdlet.ParameterSetName
if ($authMode -eq 'Config') {
    $cfg = Get-MrmConfig -Path $ConfigPath
    foreach ($n in @('TenantId','ClientId','TargetRetentionId','MailboxCsv','OutputDirectory','ThrottleDelayMs','CertificateThumbprint','CertificateStore','CertificatePath')) {
        if (-not $PSBoundParameters.ContainsKey($n) -and $cfg.PSObject.Properties[$n] -and
            $null -ne $cfg.$n -and '' -ne [string]$cfg.$n) {
            Set-Variable -Name $n -Value $cfg.$n -WhatIf:$false -Confirm:$false
        }
    }
    if (-not $ClientSecret        -and $cfg.PSObject.Properties['ClientSecret']        -and $cfg.ClientSecret)        { $ClientSecret        = $cfg.ClientSecret }
    if (-not $CertificatePassword -and $cfg.PSObject.Properties['CertificatePassword'] -and $cfg.CertificatePassword) { $CertificatePassword = $cfg.CertificatePassword }
    foreach ($req in @('TenantId','ClientId')) {
        if (-not (Get-Variable -Name $req -ValueOnly)) { throw "Config/CLI is missing required setting: ${req} (${ConfigPath})" }
    }
    $authMode = if ($CertificateThumbprint) { 'Certificate' }
                elseif ($CertificatePath)   { 'CertificateFile' }
                elseif ($ClientSecret)      { 'Secret' }
                else { throw "Config ${ConfigPath} provides no authentication material." }
    Write-MrmLog -Level Info -Message "Config loaded: ${ConfigPath} (auth mode: ${authMode}; secrets never logged)."
}
if (-not $TargetRetentionId) { throw 'TargetRetentionId is required (CLI or config).' }
$tgt = Test-MrmTargetRetentionId -TargetRetentionId $TargetRetentionId   # protected list enforced - this is a MUTATION tool

New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
$log = Join-Path $OutputDirectory 'tenant-repair.log'

# --- auth material ------------------------------------------------------------
$cert = $null
switch ($authMode) {
    'Certificate' {
        $cert = Get-ChildItem $CertificateStore | Where-Object Thumbprint -eq $CertificateThumbprint
        if (-not $cert) { throw "Certificate ${CertificateThumbprint} not found in ${CertificateStore}." }
    }
    'CertificateFile' {
        $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
            $CertificatePath,
            $(if ($CertificatePassword) { [System.Net.NetworkCredential]::new('', $CertificatePassword).Password } else { '' }),
            [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::EphemeralKeySet)
    }
    'Secret' {
        Write-MrmLog -LogPath $log -Level Warning -Message 'Client-secret auth in use - certificate auth is preferred.'
    }
}
function Get-RepairToken {
    param([Parameter(Mandatory)][string]$Scope, [switch]$Force)
    $splat = @{ TenantId = $TenantId; ClientId = $ClientId; Scope = $Scope; Force = $Force }
    if ($cert) { $splat.Certificate = $cert } else { $splat.ClientSecret = $ClientSecret }
    Get-MrmAccessToken @splat
}

# --- mailbox selection --------------------------------------------------------
$targets = [System.Collections.Generic.List[string]]::new()
if ($Mailbox) { foreach ($m in (Split-MrmMailboxList -InputList $Mailbox)) { $targets.Add($m) } }
if ($MailboxCsv) {
    if (-not (Test-Path $MailboxCsv)) { throw "Mailbox CSV not found: ${MailboxCsv}" }
    $rows = Import-Csv -Path $MailboxCsv
    if (-not $rows) { throw "Mailbox CSV is empty: ${MailboxCsv}" }
    $col = @('Mailbox','UserPrincipalName','PrimarySmtpAddress','Mail') |
           Where-Object { $rows[0].PSObject.Properties[$_] } | Select-Object -First 1
    if (-not $col) { throw 'Mailbox CSV needs one of: Mailbox, UserPrincipalName, PrimarySmtpAddress, Mail' }
    foreach ($r in $rows) { if ($r.$col) { $targets.Add(([string]$r.$col).Trim()) } }
}
if ($AllMailboxes) {
    $graphTp = { param([switch]$Force) Get-RepairToken -Scope 'https://graph.microsoft.com/.default' -Force:$Force }
    foreach ($u in @(Get-MrmGraphMailboxList -TokenProvider $graphTp -IncludeDisabled:$IncludeDisabled)) { $targets.Add($u.Mail) }
}
$targets = @($targets | Where-Object { $_ } | Sort-Object -Unique)
if (-not $targets) { throw 'No mailboxes selected. Mode 1: -Mailbox / -MailboxCsv. Mode 2: -AllMailboxes.' }

if ($runMode -eq 'TestRun') {
    $allCount = $targets.Count
    $targets = @($targets | Select-Object -First $TestRunMailboxLimit)
    Write-MrmLog -LogPath $log -Level Warning -Message "TESTRUN: limited to $($targets.Count)/$allCount mailbox(es), max ${TestRunFolderLimit} folder(s) each."
}

# --- one explicit confirmation for the whole scope (inner calls run unattended)
$scopeText = "${runMode} | target ${tgt} | $($targets.Count) mailbox(es)"
Write-MrmLog -LogPath $log -Level Info -Message "SCOPE: ${scopeText}"
if ($runMode -ne 'DryRun') {
    if (-not $PSCmdlet.ShouldProcess($scopeText, 'Remove physical PolicyTag (native EWS PolicyTag=null) with per-folder READ->BACKUP->SET->READ->COMPARE')) {
        Write-MrmLog -LogPath $log -Level Warning -Message 'Aborted by operator / -WhatIf. No changes made.'
        return
    }
}

# --- per-mailbox loop ---------------------------------------------------------
$summary = [System.Collections.Generic.List[object]]::new()
$done = 0
foreach ($m in $targets) {
    $done++
    Write-Progress -Activity "Tenant tag repair (${runMode})" -Status $m -PercentComplete (100*$done/$targets.Count)
    $stem = ConvertTo-MrmSafeFileName -Name $m
    $mbxDir = Join-Path (Join-Path $OutputDirectory 'logging') $stem
    New-Item -ItemType Directory -Force -Path $mbxDir | Out-Null
    try {
        $token   = Get-RepairToken -Scope 'https://outlook.office365.com/.default'
        $service = Connect-MrmEwsService -Mailbox $m -AccessToken $token

        # READ #1 - full census, persisted as the pre-state backup for this mailbox
        $census = Get-MrmFolderCensus -Service $service
        Export-MrmEvidence -Records $census -OutputDirectory $mbxDir -BaseName 'pre-census' | Out-Null

        # SAFETY NET (fail-closed): complete per-mailbox tag-state backup JSON,
        # written AND read back before any write. No verified backup => no writes
        # for this mailbox.
        $stampedCount = @($census | Where-Object {
            ($_.PSObject.Properties['PolicyTagRetentionId']  -and $_.PolicyTagRetentionId) -or
            ($_.PSObject.Properties['ArchiveTagRetentionId'] -and $_.ArchiveTagRetentionId) }).Count
        $backupPath = Export-MrmTagStateBackup -Mailbox $m -Census $census -Directory $mbxDir -TargetRetentionId $tgt
        if (-not (Test-MrmTagStateBackup -Path $backupPath -Mailbox $m -ExpectedStampedCount $stampedCount)) {
            if ($runMode -ne 'DryRun') {
                throw "SAFETY NET FAILED: tag-state backup not verifiable (${backupPath}) - refusing to write in this mailbox."
            }
            Write-MrmLog -LogPath $log -Level Warning -Message "Backup not verifiable (${backupPath}) - DryRun continues, but fix this before -TestRun/-Apply."
        } else {
            Write-MrmLog -LogPath $log -Level Info -Message "Safety-net backup verified: ${backupPath} (${stampedCount} stamped folder(s))."
        }

        if ($runMode -eq 'DryRun') {
            $r = Invoke-MrmFolderUntag -Service $service -Census $census -TargetRetentionId $tgt `
                     -SnapshotDirectory $mbxDir -LogPath $log -Confirm:$false
            $summary.Add([pscustomobject]@{ Mailbox=$m; Mode='DryRun'
                Candidates=@($r.Candidates).Count; Changed=0; Verified=0; Unverified=0
                SkippedOtherTags=@($r.Skipped).Count; Error=$null })
        }
        else {
            $censusForRun = $census
            if ($runMode -eq 'TestRun') {
                # cap: only the first N candidate folders take part; everything
                # else is not even offered to the untag function
                $cand   = @($census | Where-Object { $_.HasPhysicalPolicyTag -and $_.PolicyTagRetentionId -eq $tgt } |
                            Select-Object -First $TestRunFolderLimit)
                $others = @($census | Where-Object { -not ($_.HasPhysicalPolicyTag -and $_.PolicyTagRetentionId -eq $tgt) })
                $censusForRun = @($cand + $others)
                Write-MrmLog -LogPath $log -Level Warning -Message "TESTRUN ${m}: offering $(@($cand).Count) candidate folder(s) to the evidence cell."
            }
            $r = Invoke-MrmFolderUntag -Service $service -Census $censusForRun -TargetRetentionId $tgt `
                     -Apply -SnapshotDirectory $mbxDir -LogPath $log -Confirm:$false

            # READ #2 + COMPARE happened inside per folder (Verified). Re-census
            # for the mailbox-level after-picture:
            $post = Get-MrmFolderCensus -Service $service
            Export-MrmEvidence -Records $post -OutputDirectory $mbxDir -BaseName 'post-census' | Out-Null
            $remaining = @($post | Where-Object { $_.HasPhysicalPolicyTag -and $_.PolicyTagRetentionId -eq $tgt }).Count

            $verified   = @($r.Changed | Where-Object { $_.Verified }).Count
            $unverified = @($r.Changed | Where-Object { -not $_.Verified }).Count
            $summary.Add([pscustomobject]@{ Mailbox=$m; Mode=$runMode
                Candidates=@($r.Candidates).Count; Changed=@($r.Changed).Count
                Verified=$verified; Unverified=$unverified
                SkippedOtherTags=@($r.Skipped).Count
                Error=$(if ($unverified) { 'POST-WRITE STATE UNEXPECTED - inspect JSONL' }
                        elseif ($runMode -eq 'Apply' -and $remaining -gt 0) { "post-census still shows ${remaining} tagged folder(s)" }
                        else { $null }) })
        }
    }
    catch {
        $summary.Add([pscustomobject]@{ Mailbox=$m; Mode=$runMode; Candidates=$null; Changed=$null
            Verified=$null; Unverified=$null; SkippedOtherTags=$null; Error=$_.Exception.Message })
        Write-MrmLog -LogPath $log -Level Warning -Message "${m} FAILED (continuing): $($_.Exception.Message)"
    }
    if ($ThrottleDelayMs -gt 0) { Start-Sleep -Milliseconds $ThrottleDelayMs }
}
Write-Progress -Activity "Tenant tag repair (${runMode})" -Completed

# --- tenant summary -----------------------------------------------------------
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$sumCsv  = Join-Path $OutputDirectory "tenant-repair-summary-${runMode}-${stamp}.csv"
$sumJson = Join-Path $OutputDirectory "tenant-repair-summary-${runMode}-${stamp}.json"
$summary | Export-Csv -Path $sumCsv -NoTypeInformation -Encoding utf8
@{ GeneratedUtc=[DateTime]::UtcNow.ToString('o'); Mode=$runMode; Target=$tgt; Summary=$summary } |
    ConvertTo-Json -Depth 6 | Set-Content -Path $sumJson -Encoding UTF8

Write-Host ''
Write-Host "================ TENANT TAG REPAIR - ${runMode} ================" -ForegroundColor Cyan
$summary | Format-Table Mailbox, Mode, Candidates, Changed, Verified, Unverified, SkippedOtherTags, Error -AutoSize |
    Out-String -Width 220 | Write-Host
Write-Host "Evidence cell per mutated folder: READ -> BACKUP (untag-changes-*.jsonl) -> SET -> READ -> COMPARE (Verified)." -ForegroundColor Cyan
Write-Host "Per-mailbox pre/post censuses + JSONL backups: ${OutputDirectory}\<mailbox>\" -ForegroundColor Cyan
switch ($runMode) {
    'DryRun'  { Write-Host 'Nothing was modified. Next step: -TestRun (1 folder in 1 mailbox by default).' -ForegroundColor Green }
    'TestRun' { Write-Host "Test run done. Inspect the JSONL before/after pairs, then widen limits or go -Apply." -ForegroundColor Yellow }
    'Apply'   { Write-Host 'Full run done. Verify externally: Get-MailboxFolderStatistics -IncludeAnalysis. NO MFA re-enable from here.' -ForegroundColor Yellow }
}
