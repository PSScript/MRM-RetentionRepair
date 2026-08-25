#Requires -Version 5.1
<#
.SYNOPSIS
Tenant-wide READ-ONLY report of physically stamped retention tags (delete AND
archive) across user mailboxes — a modernized ReportTagged.ps1
(gscales/Powershell-Scripts), deliberately "oldschool": raw OAuth + EWS Managed
API + raw Graph REST for discovery. NO Microsoft.Graph module.

.DESCRIPTION
Improvements over the original ReportTagged.ps1:
  * app-only OAuth (certificate preferred) instead of Basic-Auth credentials
  * explicit https://outlook.office365.com endpoint instead of Autodiscover
  * many mailboxes per run: -Mailbox list, -MailboxCsv, or -DiscoverViaGraph
    (raw Graph REST /users paging; needs application permission User.Read.All)
  * keeps the original's core insight intact: PHYSICAL stamps
    (Exists(PR_POLICY_TAG 0x3019)) are reported separately from what merely
    LOOKS tagged — plus 0x301A period, 0x301D flags decoded, 0x3018 archive tag
  * .NET Guid byte conversion (unit-proven byte-identical to the original's
    manual hex shuffle)
  * structured evidence: per-mailbox JSON, consolidated CSV, tenant rollup
    (CSV+JSON), -Resume to continue an interrupted run
  * throttling-aware (bounded backoff), per-mailbox error isolation
  * STRICTLY read-only — the AST test suite forbids every mutating cmdlet

.EXAMPLE
    ./Invoke-MrmTenantTagReport.ps1 -ConfigPath ./configs/TENANT-A.json -DiscoverViaGraph
.EXAMPLE
    ./Invoke-MrmTenantTagReport.ps1 -ConfigPath ./configs/TENANT-A.json `
        -MailboxCsv ./mailboxes.csv -FilterRetentionId d94993b5-e987-4275-8707-072057cfb2b8 -Resume
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

    # ---- mailbox sources (any combination; duplicates removed) ----
    [string[]]$Mailbox,
    [string]$MailboxCsv,          # column: Mailbox | UserPrincipalName | PrimarySmtpAddress | Mail (auto-detected)
    [switch]$DiscoverViaGraph,    # raw Graph REST /users (User.Read.All), no Mg module
    [switch]$IncludeDisabled,     # discovery: include accountEnabled=false

    # ---- report shaping ----
    [string]$FilterRetentionId,   # only report folders physically stamped with THIS tag
    [switch]$Resume,              # skip mailboxes that already have a per-mailbox JSON
    [int]$ThrottleDelayMs = 250,  # polite inter-mailbox pause
    [string]$OutputDirectory = (Join-Path $PSScriptRoot 'evidence\tenant-report')
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'MRM-RetentionRepair.psm1') -Force

# --- Config mode: JSON settings, CLI overrides config ------------------------
$authMode = $PSCmdlet.ParameterSetName
if ($authMode -eq 'Config') {
    $cfg = Get-MrmConfig -Path $ConfigPath
    foreach ($n in @('TenantId','ClientId','OutputDirectory','MailboxCsv','FilterRetentionId','ThrottleDelayMs','CertificateThumbprint','CertificateStore','CertificatePath')) {
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

New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
$perMbxDir = Join-Path $OutputDirectory 'logging'
New-Item -ItemType Directory -Force -Path $perMbxDir | Out-Null
$log = Join-Path $OutputDirectory 'tenant-report.log'

if ($FilterRetentionId) {
    # NB: for a REPORT any valid GUID is fine — including protected ones; this
    # is read-only. We only canonicalize here, we do not apply removal rules.
    $g=[Guid]::Empty
    if (-not [Guid]::TryParse($FilterRetentionId,[ref]$g)) { throw "FilterRetentionId is not a GUID: ${FilterRetentionId}" }
    $FilterRetentionId = $g.ToString().ToLowerInvariant()
}

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
        Write-MrmLog -LogPath $log -Level Warning -Message 'Client-secret auth in use — certificate auth is preferred.'
    }
}
function Get-ReportToken {
    param([Parameter(Mandatory)][string]$Scope, [switch]$Force)
    $splat = @{ TenantId = $TenantId; ClientId = $ClientId; Scope = $Scope; Force = $Force }
    if ($cert) { $splat.Certificate = $cert } else { $splat.ClientSecret = $ClientSecret }
    Get-MrmAccessToken @splat
}

# --- assemble the mailbox list -----------------------------------------------
$targets = [System.Collections.Generic.List[string]]::new()
if ($Mailbox)    { foreach ($m in $Mailbox) { $targets.Add($m.Trim()) } }
if ($MailboxCsv) {
    if (-not (Test-Path $MailboxCsv)) { throw "Mailbox CSV not found: ${MailboxCsv}" }
    $rows = Import-Csv -Path $MailboxCsv
    if (-not $rows) { throw "Mailbox CSV is empty: ${MailboxCsv}" }
    $col = @('Mailbox','UserPrincipalName','PrimarySmtpAddress','Mail') |
           Where-Object { $rows[0].PSObject.Properties[$_] } | Select-Object -First 1
    if (-not $col) { throw "Mailbox CSV needs one of these columns: Mailbox, UserPrincipalName, PrimarySmtpAddress, Mail" }
    foreach ($r in $rows) { if ($r.$col) { $targets.Add(([string]$r.$col).Trim()) } }
    Write-MrmLog -LogPath $log -Level Info -Message "CSV ${MailboxCsv}: column '${col}', $($rows.Count) rows."
}
if ($DiscoverViaGraph) {
    $graphTp = { param([switch]$Force) Get-ReportToken -Scope 'https://graph.microsoft.com/.default' -Force:$Force }
    $found = @(Get-MrmGraphMailboxList -TokenProvider $graphTp -IncludeDisabled:$IncludeDisabled)
    foreach ($u in $found) { $targets.Add($u.Mail) }
}
$targets = @($targets | Where-Object { $_ } | Sort-Object -Unique)
if (-not $targets) { throw 'No mailboxes to report on. Provide -Mailbox, -MailboxCsv and/or -DiscoverViaGraph.' }
Write-MrmLog -LogPath $log -Level Info -Message "Tenant report over $($targets.Count) mailbox(es). Filter: $(if ($FilterRetentionId) { $FilterRetentionId } else { '<none — all physical tags>' })"

# --- per-mailbox census (READ-ONLY) ------------------------------------------
$allRecords = [System.Collections.Generic.List[object]]::new()
$errors     = [System.Collections.Generic.List[object]]::new()
$done = 0
foreach ($m in $targets) {
    $done++
    $stem = ConvertTo-MrmSafeFileName -Name $m
    $perFile = Join-Path $perMbxDir "${stem}.json"
    if ($Resume -and (Test-Path $perFile)) {
        Write-MrmLog -LogPath $log -Level Info -Message "[$done/$($targets.Count)] RESUME skip: ${m}"
        foreach ($r in (Get-Content $perFile -Raw | ConvertFrom-Json)) { $allRecords.Add($r) }
        continue
    }
    Write-Progress -Activity 'Tenant retention-tag report' -Status $m -PercentComplete (100*$done/$targets.Count)
    try {
        $token   = Get-ReportToken -Scope 'https://outlook.office365.com/.default'
        $service = Connect-MrmEwsService -Mailbox $m -AccessToken $token
        $census  = Get-MrmFolderCensus -Service $service
        $rows = foreach ($c in $census) {
            $c | Add-Member -NotePropertyName Mailbox -NotePropertyValue $m -PassThru
        }
        if ($FilterRetentionId) {
            $rows = @($rows | Where-Object {
                ($_.PSObject.Properties['PolicyTagRetentionId']  -and $_.PolicyTagRetentionId  -eq $FilterRetentionId) -or
                ($_.PSObject.Properties['ArchiveTagRetentionId'] -and $_.ArchiveTagRetentionId -eq $FilterRetentionId) })
        } else {
            # tenant report = only folders that carry ANY physical stamp
            $rows = @($rows | Where-Object {
                ($_.PSObject.Properties['PolicyTagRetentionId']  -and $_.PolicyTagRetentionId) -or
                ($_.PSObject.Properties['ArchiveTagRetentionId'] -and $_.ArchiveTagRetentionId) })
        }
        ($rows | ConvertTo-Json -Depth 6) | Set-Content -Path $perFile -Encoding UTF8
        foreach ($r in $rows) { $allRecords.Add($r) }
        Write-MrmLog -LogPath $log -Level Info -Message "[$done/$($targets.Count)] ${m}: $($rows.Count) physically stamped folder(s)."
    }
    catch {
        $errors.Add([pscustomobject]@{ Mailbox = $m; Error = $_.Exception.Message; WhenUtc = [DateTime]::UtcNow.ToString('o') })
        Write-MrmLog -LogPath $log -Level Warning -Message "[$done/$($targets.Count)] ${m} FAILED (continuing): $($_.Exception.Message)"
    }
    if ($ThrottleDelayMs -gt 0) { Start-Sleep -Milliseconds $ThrottleDelayMs }
}
Write-Progress -Activity 'Tenant retention-tag report' -Completed

# --- consolidated evidence + rollup ------------------------------------------
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
if ($allRecords.Count -gt 0) {
    $csv = Join-Path $OutputDirectory "tenant-tagged-folders-${stamp}.csv"
    $allRecords |
        Select-Object Mailbox, FolderPath, DisplayName, PolicyTagRetentionId, RetentionPeriod,
                      RetentionFlagsRaw, RetentionFlagsDecoded, ArchiveTagRetentionId,
                      TotalItemCount, ExistsFilterHit |
        Export-Csv -Path $csv -NoTypeInformation -Encoding utf8
    Write-MrmLog -LogPath $log -Level Info -Message "Consolidated CSV: ${csv} ($($allRecords.Count) rows)"
}
$rollup = @(Get-MrmTenantTagRollup -Records $allRecords)
$rollupCsv  = Join-Path $OutputDirectory "tenant-tag-rollup-${stamp}.csv"
$rollupJson = Join-Path $OutputDirectory "tenant-tag-rollup-${stamp}.json"
if ($rollup.Count -gt 0) { $rollup | Export-Csv -Path $rollupCsv -NoTypeInformation -Encoding utf8 }
@{ GeneratedUtc = [DateTime]::UtcNow.ToString('o')
   MailboxesRequested = $targets.Count
   MailboxesFailed    = $errors.Count
   Filter             = $FilterRetentionId
   Rollup             = $rollup
   Errors             = $errors } | ConvertTo-Json -Depth 8 | Set-Content -Path $rollupJson -Encoding UTF8

Write-Host ''
Write-Host '================ TENANT RETENTION TAG ROLLUP (physical stamps) ================' -ForegroundColor Cyan
if (@($rollup).Count -eq 0) {
    Write-Host 'No physically stamped folders found in the scanned mailboxes.' -ForegroundColor Green
} else {
    $rollup | Format-Table Kind, RetentionId, FolderCount, MailboxCount, PeriodsDays, FlagsSeen -AutoSize | Out-String -Width 220 | Write-Host
}
if ($errors.Count -gt 0) {
    Write-Host "FAILED mailboxes: $($errors.Count) (see rollup JSON / log)" -ForegroundColor Yellow
}
Write-Host "Evidence: ${OutputDirectory}" -ForegroundColor Cyan
Write-Host 'Read-only run — nothing was modified. Effective-vs-physical caveat:' -ForegroundColor Cyan
Write-Host 'folders inheriting a tag WITHOUT a physical 0x3019/0x3018 stamp do not appear here (by design, as in ReportTagged.ps1).' -ForegroundColor Cyan
