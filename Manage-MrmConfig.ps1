#Requires -Version 5.1
<#
.SYNOPSIS
Configuration management for MRM-RetentionRepair (Create / Test / List / Show / Encrypt).

Same ergonomics as PSScript/Resend-GraphReplay's Manage-GraphReplayConfig.ps1:
one JSON file per tenant/run, secrets stored DPAPI-encrypted
(ConvertFrom-SecureString — bound to the creating user+machine on Windows),
never plaintext on disk, never echoed to console.

.EXAMPLE
    ./Manage-MrmConfig.ps1 -Action Create -ConfigPath ./configs/TENANT-A.json
    ./Manage-MrmConfig.ps1 -Action Test   -ConfigPath ./configs/TENANT-A.json
    ./Manage-MrmConfig.ps1 -Action Show   -ConfigPath ./configs/TENANT-A.json
    ./Manage-MrmConfig.ps1 -Action List   -ConfigDirectory ./configs
    ./Manage-MrmConfig.ps1 -Action Encrypt -ConfigPath ./configs/TENANT-A.json   # plaintext -> DPAPI
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('Create','Test','List','Show','Encrypt')]
    [string]$Action,

    [string]$ConfigPath,
    [string]$ConfigDirectory = (Join-Path $PSScriptRoot 'configs')
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'MRM-RetentionRepair.psm1') -Force

if (-not (Test-Path $ConfigDirectory)) { New-Item -ItemType Directory -Path $ConfigDirectory -Force | Out-Null }

function Read-OptionalValue {
    param([string]$Prompt, [string]$Default = '')
    $v = Read-Host ($(if ($Default) { "${Prompt} [${Default}]" } else { $Prompt }))
    if ($v) { return $v } else { return $Default }
}

switch ($Action) {

    'Create' {
        if (-not $ConfigPath) { throw 'Create requires -ConfigPath (e.g. ./configs/TENANT-A.json).' }
        Write-Host 'Creating new MRM-RetentionRepair configuration' -ForegroundColor Cyan
        $cfg = [ordered]@{}

        $cfg.TenantId          = Read-Host 'Tenant ID (required)'
        $cfg.ClientId          = Read-Host 'Client ID / App ID (required)'
        $cfg.Mailbox           = Read-Host 'Target mailbox UPN (required)'
        $cfg.TargetRetentionId = Read-Host 'Target RetentionId GUID to remove (required)'
        # validate early — this also refuses protected GUIDs at config time
        $null = Test-MrmTargetRetentionId -TargetRetentionId $cfg.TargetRetentionId

        Write-Host "`nAuthentication — pick ONE (certificate preferred):" -ForegroundColor Yellow
        $thumb = Read-OptionalValue -Prompt 'Certificate thumbprint (Cert:\CurrentUser\My)'
        if ($thumb) {
            $cfg.CertificateThumbprint = $thumb
            $store = Read-OptionalValue -Prompt 'Certificate store' -Default 'Cert:\CurrentUser\My'
            $cfg.CertificateStore = $store
        } else {
            $pfx = Read-OptionalValue -Prompt 'PFX path (Enter = use client secret instead)'
            if ($pfx) {
                $cfg.CertificatePath = $pfx
                $pw = Read-Host 'PFX password (input hidden; Enter = none)' -AsSecureString
                if ($pw.Length -gt 0) { $cfg.CertificatePasswordEncrypted = Protect-MrmSecretString -Secret $pw }
            } else {
                $sec = Read-Host 'Client secret (input hidden)' -AsSecureString
                if ($sec.Length -eq 0) { throw 'No authentication material provided.' }
                $cfg.ClientSecretEncrypted = Protect-MrmSecretString -Secret $sec
                Write-Host 'NOTE: client secret is DISCOURAGED — prefer certificates.' -ForegroundColor Yellow
            }
        }

        Write-Host "`nOptional settings (Enter to skip):" -ForegroundColor Yellow
        $kec = Read-OptionalValue -Prompt 'KnownEffectiveCount (folders showing the tag in Get-MailboxFolderStatistics)'
        if ($kec) { $cfg.KnownEffectiveCount = [int]$kec }
        $od = Read-OptionalValue -Prompt 'OutputDirectory' -Default (Join-Path $PSScriptRoot 'evidence')
        $cfg.OutputDirectory = $od
        $cfg.Description = Read-OptionalValue -Prompt 'Description'
        $cfg.CreatedDate = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        $cfg.CreatedBy   = $env:USERNAME

        ($cfg | ConvertTo-Json -Depth 5) | Set-Content -Path $ConfigPath -Encoding UTF8
        Write-Host "Saved: ${ConfigPath} (secret DPAPI-encrypted, user+machine bound)" -ForegroundColor Green
    }

    'Encrypt' {
        if (-not $ConfigPath) { throw 'Encrypt requires -ConfigPath.' }
        $raw = Get-Content $ConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json
        $changed = $false
        if ($raw.PSObject.Properties['ClientSecret'] -and $raw.ClientSecret) {
            $sec = ConvertTo-SecureString -String $raw.ClientSecret -AsPlainText -Force
            $raw | Add-Member -NotePropertyName ClientSecretEncrypted -NotePropertyValue (Protect-MrmSecretString -Secret $sec) -Force
            $raw.PSObject.Properties.Remove('ClientSecret')
            $changed = $true
        }
        if (-not $changed) {
            $sec = Read-Host 'New client secret (input hidden)' -AsSecureString
            if ($sec.Length -eq 0) { throw 'Nothing to encrypt.' }
            $raw | Add-Member -NotePropertyName ClientSecretEncrypted -NotePropertyValue (Protect-MrmSecretString -Secret $sec) -Force
        }
        ($raw | ConvertTo-Json -Depth 5) | Set-Content -Path $ConfigPath -Encoding UTF8
        Write-Host "Encrypted and saved: ${ConfigPath}" -ForegroundColor Green
    }

    'List' {
        Get-ChildItem -Path $ConfigDirectory -Filter '*.json' -ErrorAction SilentlyContinue | ForEach-Object {
            try {
                $c = Get-Content $_.FullName -Raw -Encoding UTF8 | ConvertFrom-Json
                [pscustomobject]@{
                    Config      = $_.Name
                    TenantId    = $c.TenantId
                    Mailbox     = $c.Mailbox
                    Auth        = if ($c.PSObject.Properties['CertificateThumbprint']) { 'Cert (store)' }
                                  elseif ($c.PSObject.Properties['CertificatePath'])  { 'Cert (PFX)' }
                                  elseif ($c.PSObject.Properties['ClientSecretEncrypted']) { 'Secret (DPAPI)' }
                                  elseif ($c.PSObject.Properties['ClientSecret']) { 'Secret (PLAINTEXT!)' }
                                  else { '-' }
                    Description = $(if ($c.PSObject.Properties['Description']) { $c.Description } else { '' })
                }
            } catch { Write-Warning "Unreadable config: $($_.FullName)" }
        } | Format-Table -AutoSize
    }

    'Show' {
        if (-not $ConfigPath) { throw 'Show requires -ConfigPath.' }
        $c = Get-Content $ConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json
        foreach ($p in $c.PSObject.Properties) {
            $v = $p.Value
            if ($p.Name -match 'Secret|Password') { $v = '***' + $(if ($p.Name -match 'Encrypted') { ' (DPAPI)' } else { ' (PLAINTEXT — run -Action Encrypt!)' }) }
            Write-Host ("{0,-32} {1}" -f $p.Name, $v)
        }
    }

    'Test' {
        if (-not $ConfigPath) { throw 'Test requires -ConfigPath.' }
        $cfg = Get-MrmConfig -Path $ConfigPath
        Write-Host "Config loaded: $(Split-Path $ConfigPath -Leaf)" -ForegroundColor Cyan
        foreach ($req in 'TenantId','ClientId','Mailbox','TargetRetentionId') {
            if (-not ($cfg.PSObject.Properties[$req] -and $cfg.$req)) { throw "Missing required field: ${req}" }
        }
        $null = Test-MrmTargetRetentionId -TargetRetentionId $cfg.TargetRetentionId
        Write-Host '[ok] required fields + target GUID valid (and not a protected tag)' -ForegroundColor Green

        # token smoke tests (no mailbox access — pure auth)
        $cert = $null
        if ($cfg.PSObject.Properties['CertificateThumbprint'] -and $cfg.CertificateThumbprint) {
            $store = if ($cfg.PSObject.Properties['CertificateStore'] -and $cfg.CertificateStore) { $cfg.CertificateStore } else { 'Cert:\CurrentUser\My' }
            $cert = Get-Item (Join-Path $store $cfg.CertificateThumbprint)
        } elseif ($cfg.PSObject.Properties['CertificatePath'] -and $cfg.CertificatePath) {
            $pwPlain = if ($cfg.PSObject.Properties['CertificatePassword'] -and $cfg.CertificatePassword) {
                [System.Net.NetworkCredential]::new('', $cfg.CertificatePassword).Password } else { '' }
            $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 `
                        -ArgumentList $cfg.CertificatePath, $pwPlain,
                        ([System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::EphemeralKeySet)
        }
        foreach ($scope in 'https://outlook.office365.com/.default','https://graph.microsoft.com/.default') {
            $splat = @{ TenantId = $cfg.TenantId; ClientId = $cfg.ClientId; Scope = $scope; Force = $true }
            if ($cert) { $splat.Certificate = $cert }
            elseif ($cfg.PSObject.Properties['ClientSecret'] -and $cfg.ClientSecret) { $splat.ClientSecret = $cfg.ClientSecret }
            else { throw 'No usable authentication material in config.' }
            $null = Get-MrmAccessToken @splat
            Write-Host "[ok] app-only token acquired for ${scope}" -ForegroundColor Green
        }
        Write-Host 'Config test PASSED.' -ForegroundColor Green
    }
}
