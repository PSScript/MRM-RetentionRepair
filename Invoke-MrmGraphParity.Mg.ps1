#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication
<#
.SYNOPSIS
Phase 2 (Graph parity) - Microsoft.Graph SDK variant.

Identical audit logic to Invoke-MrmGraphParity.ps1, but authentication and HTTP
are delegated to the Microsoft.Graph PowerShell SDK (Connect-MgGraph /
Invoke-MgGraphRequest). Use this where the SDK is the sanctioned client stack.
The token-based sibling script has ZERO module dependencies and remains the
default. Both feed the same module functions, so parity evidence is identical.

.EXAMPLE
    ./Invoke-MrmGraphParity.Mg.ps1 -TenantId <tid> -ClientId <app> `
        -CertificateThumbprint <tp> -Mailbox user@contoso.com `
        -TargetRetentionId d94993b5-e987-4275-8707-072057cfb2b8 `
        -EwsCensusJson ./evidence/folder-census-<ts>.json
#>
[CmdletBinding(DefaultParameterSetName='Certificate')]
param(
    [Parameter(Mandatory, ParameterSetName='Certificate')][Parameter(Mandatory, ParameterSetName='Secret')]
    [Parameter(ParameterSetName='Config')][string]$TenantId,
    [Parameter(Mandatory, ParameterSetName='Certificate')][Parameter(Mandatory, ParameterSetName='Secret')]
    [Parameter(ParameterSetName='Config')][string]$ClientId,
    [Parameter(Mandatory, ParameterSetName='Certificate')][string]$CertificateThumbprint,
    [Parameter(Mandatory, ParameterSetName='Secret')][securestring]$ClientSecret,
    [Parameter(Mandatory, ParameterSetName='Config')][string]$ConfigPath,
    [Parameter(Mandatory, ParameterSetName='Certificate')][Parameter(Mandatory, ParameterSetName='Secret')]
    [Parameter(ParameterSetName='Config')][string]$Mailbox,
    [Parameter(Mandatory, ParameterSetName='Certificate')][Parameter(Mandatory, ParameterSetName='Secret')]
    [Parameter(ParameterSetName='Config')][string]$TargetRetentionId,
    [Parameter(Mandatory, ParameterSetName='Certificate')][Parameter(Mandatory, ParameterSetName='Secret')]
    [Parameter(ParameterSetName='Config')][string]$EwsCensusJson,
    [string]$EvidenceDirectory = (Join-Path (Get-Location) 'evidence'),
    [switch]$IncludeHidden,
    # ---- Gate 8 (experimental, disposable folder only) ----
    [switch]$ExperimentalWriteProbe,
    [string]$ProbeGraphFolderId,
    [switch]$IUnderstandThisIsAnExperiment
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'MRM-RetentionRepair.psm1') -Force

# --- Config mode: JSON settings, CLI overrides config -----------------------
$authMode = $PSCmdlet.ParameterSetName
if ($authMode -eq 'Config') {
    $cfg = Get-MrmConfig -Path $ConfigPath
    foreach ($n in @('TenantId','ClientId','Mailbox','TargetRetentionId','EwsCensusJson','EvidenceDirectory','CertificateThumbprint')) {
        if (-not $PSBoundParameters.ContainsKey($n) -and $cfg.PSObject.Properties[$n] -and
            $null -ne $cfg.$n -and '' -ne [string]$cfg.$n) {
            Set-Variable -Name $n -Value $cfg.$n -WhatIf:$false -Confirm:$false
        }
    }
    if (-not $ClientSecret -and $cfg.PSObject.Properties['ClientSecret'] -and $cfg.ClientSecret) { $ClientSecret = $cfg.ClientSecret }
    foreach ($req in @('TenantId','ClientId','Mailbox','TargetRetentionId','EwsCensusJson')) {
        if (-not (Get-Variable -Name $req -ValueOnly)) { throw "Config/CLI is missing required setting: ${req} (${ConfigPath})" }
    }
    $authMode = if ($CertificateThumbprint) { 'Certificate' } elseif ($ClientSecret) { 'Secret' }
                else { throw "Config ${ConfigPath} provides no authentication material." }
    Write-MrmLog -Level Info -Message "Config loaded: ${ConfigPath} (auth mode: ${authMode}; secrets never logged)."
}

# --- Connect via SDK (app-only) -------------------------------------------
if ($authMode -eq 'Certificate') {
    Connect-MgGraph -TenantId $TenantId -ClientId $ClientId `
        -CertificateThumbprint $CertificateThumbprint -NoWelcome
} else {
    $cred = New-Object System.Management.Automation.PSCredential($ClientId, $ClientSecret)
    Connect-MgGraph -TenantId $TenantId -ClientSecretCredential $cred -NoWelcome
}
$ctx = Get-MgContext
if (-not $ctx -or $ctx.AuthType -ne 'AppOnly') {
    throw 'Connect-MgGraph did not yield an app-only context.'
}
Write-MrmLog -Level Info -Message "Gate 7 [Mg]: connected app-only as $($ctx.ClientId) ($($ctx.TenantId))."

# --- SDK-backed request handler: same shape Invoke-MrmGraphCall expects ----
$handler = {
    param($Uri, $Method, $Body)
    if ($null -eq $Method -or $Method -eq '') { $Method = 'GET' }
    $splat = @{ Uri = $Uri; Method = $Method; OutputType = 'PSObject' }
    if ($null -ne $Body) { $splat.Body = ($Body | ConvertTo-Json -Depth 10) }
    Invoke-MgGraphRequest @splat
}

# --- Same evidence flow as the token variant -------------------------------
$Target = Test-MrmTargetRetentionId -TargetRetentionId $TargetRetentionId
if (-not (Test-Path $EwsCensusJson)) { throw "EWS census not found: ${EwsCensusJson}" }
$ewsCensus = Get-Content $EwsCensusJson -Raw | ConvertFrom-Json
if (-not (Test-Path $EvidenceDirectory)) { New-Item -ItemType Directory -Path $EvidenceDirectory -Force | Out-Null }

$graphCensus = Get-MrmGraphFolderCensus -Mailbox $Mailbox -RequestHandler $handler -IncludeHidden:$IncludeHidden
Export-MrmEvidence -Records $graphCensus -EvidenceDirectory $EvidenceDirectory -BaseName 'graph-census-mg'

$parity = Compare-MrmCensusParity -EwsCensus $ewsCensus -GraphCensus $graphCensus -TargetRetentionId $Target
$parityPath = Join-Path $EvidenceDirectory ("graph-parity-report-mg-{0:yyyyMMdd-HHmmss}.json" -f (Get-Date))
$parity | ConvertTo-Json -Depth 8 | Set-Content -Path $parityPath -Encoding utf8
Write-MrmLog -Level Info -Message "Parity report: ${parityPath}"

if ($parity.ParityOk) {
    Write-MrmLog -Level Info -Message 'Gate 7 [Mg]: PASS - Graph READ parity with the EWS oracle.'
} else {
    Write-MrmLog -Level Warning -Message 'Gate 7 [Mg]: FAIL - see report. Do NOT proceed to any write experiment.'
}

if ($ExperimentalWriteProbe) {
    if (-not $parity.ParityOk) { throw 'Refusing write probe: Gate 7 read parity failed.' }
    if (-not $ProbeGraphFolderId) { throw 'Write probe requires -ProbeGraphFolderId (a DISPOSABLE folder).' }
    $probe = Invoke-MrmGraphWriteProbe -Mailbox $Mailbox -GraphFolderId $ProbeGraphFolderId `
                -TargetRetentionId $Target -RequestHandler $handler `
                -IUnderstandThisIsAnExperiment:$IUnderstandThisIsAnExperiment
    $probePath = Join-Path $EvidenceDirectory ("graph-write-probe-mg-{0:yyyyMMdd-HHmmss}.json" -f (Get-Date))
    $probe | ConvertTo-Json -Depth 8 | Set-Content -Path $probePath -Encoding utf8
    Write-MrmLog -Level Warning -Message "Write probe evidence: ${probePath}. Graph WRITE parity remains UNPROVEN until an EWS re-read matches the Gate-5 fixture."
}
Disconnect-MgGraph | Out-Null
