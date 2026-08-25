#Requires -Version 5.1
<#
.SYNOPSIS
    MRM-RetentionRepair - surgical audit & removal of ONE mailbox-local physical
    MRM personal retention tag (PR_POLICY_TAG) via EWS Managed API 2.2 (oracle)
    with a Microsoft Graph read-parity implementation.

.DESCRIPTION
    Incident tooling. Two strict phases:
      Phase 1 (EWS)   : 1A physical-tag census (read-only)
                        1B item-level audit    (read-only)
                        1C surgical folder untag (dry-run default, -Apply gated)
      Phase 2 (Graph) : 2A read parity against the EWS census
                        2B write experiment - GATED, unproven by default.

    HARD INVARIANTS (enforced in code, verified in tests):
      * A write happens ONLY when the folder's PHYSICAL PolicyTag RetentionId
        equals the explicit -TargetRetentionId. Non-matching tags are NEVER touched.
      * The protected RetentionId 414c6a14-3ed5-432e-9edb-c6620a8278f0
        ("Never Delete") can never be a target.
      * This module contains NO tenant-level MRM cmdlets, does not start the
        Managed Folder Assistant, does not touch ElcProcessingDisabled, does not
        restore, move or delete mail, and does not modify ArchiveTag.
      * Tokens / secrets / Authorization headers are never written to logs.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ============================================================================
# Constants
# ============================================================================

# RetentionIds that may NEVER be selected as a removal target.
$script:MrmProtectedRetentionIds = @(
    '414c6a14-3ed5-432e-9edb-c6620a8278f0'   # "Never Delete" - legitimate tenant tag
)

# MAPI property tags (MS-OXPROPS / MS-OXCMSG)
$script:MrmPropTags = [ordered]@{
    PR_POLICY_TAG        = 0x3019   # Binary  - PidTagPolicyTag (delete tag GUID)
    PR_RETENTION_PERIOD  = 0x301A   # Integer - PidTagRetentionPeriod (days)
    PR_RETENTION_FLAGS   = 0x301D   # Integer - PidTagRetentionFlags
    PR_ARCHIVE_TAG       = 0x3018   # Binary  - PidTagArchiveTag (read-only here)
    PR_FOLDER_PATH       = 0x66B5   # String  - folder path, U+FFFE separators
}

# PidTagRetentionFlags bit meanings (MS-OXCMSG 2.2.1.56.3)
$script:MrmRetentionFlagBits = [ordered]@{
    0x0001 = 'ExplicitTag'
    0x0002 = 'UserOverride'
    0x0004 = 'AutoTag'
    0x0008 = 'PersonalTag'
    0x0010 = 'ExplicitArchiveTag'
    0x0020 = 'KeepInPlace'
    0x0040 = 'SystemData'
    0x0080 = 'NeedsRescan'
    0x0100 = 'PendingRescan'
}

$script:MrmTokenCache = @{}

# ============================================================================
# Logging (token-safe)
# ============================================================================

function Protect-MrmLogText {
    <# Scrubs anything that looks like a bearer token / JWT / client secret
       before it can reach a log sink. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)
    $t = $Text
    $t = [regex]::Replace($t, 'Bearer\s+[A-Za-z0-9\-\._~\+\/]+=*', 'Bearer ***REDACTED***')
    $t = [regex]::Replace($t, 'eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{5,}', '***REDACTED-JWT***')
    $t = [regex]::Replace($t, '(client_secret=)[^&\s]+', '$1***REDACTED***')
    return $t
}

function Write-MrmLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('Debug','Info','Warning','Error','Change')][string]$Level = 'Info',
        [string]$LogPath
    )
    $stamp = (Get-Date).ToString('yyyy-MM-ddTHH:mm:ss.fffK')
    $clean = Protect-MrmLogText -Text $Message
    $line  = "[${stamp}] [${Level}] ${clean}"
    switch ($Level) {
        'Error'   { Write-Host $line -ForegroundColor Red }
        'Warning' { Write-Host $line -ForegroundColor Yellow }
        'Change'  { Write-Host $line -ForegroundColor Magenta }
        'Debug'   { Write-Verbose $line }
        default   { Write-Host $line }
    }
    if ($LogPath) { Add-Content -Path $LogPath -Value $line -Encoding utf8 }
}

# ============================================================================
# GUID <-> MAPI binary conversion
# ============================================================================
# PR_POLICY_TAG stores the retention tag GUID as the 16-byte little-endian
# layout produced by System.Guid.ToByteArray():
#   bytes 0-3  : Data1 reversed
#   bytes 4-5  : Data2 reversed
#   bytes 6-7  : Data3 reversed
#   bytes 8-15 : Data4 as-is
# The System.Guid(byte[]) constructor interprets exactly this layout, so the
# .NET Guid type IS the canonical converter. Glen Scales' manual hex shuffle in
# ReportTagged.ps1 is byte-for-byte equivalent (proven in unit tests) - we do
# not cargo-cult the string shuffle.

function ConvertFrom-MrmPolicyTagBytes {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][byte[]]$Bytes)
    if ($Bytes.Count -ne 16) {
        throw "PR_POLICY_TAG must be exactly 16 bytes, got $($Bytes.Count)."
    }
    return ([Guid]::new($Bytes)).ToString().ToLowerInvariant()
}

function ConvertTo-MrmPolicyTagBytes {
    [CmdletBinding()]
    [OutputType([byte[]])]
    param([Parameter(Mandatory)][Guid]$RetentionId)
    return ,($RetentionId.ToByteArray())
}

function ConvertFrom-MrmPolicyTagBase64 {
    <# Graph returns Binary singleValueLegacyExtendedProperties as Base64. #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][string]$Base64)
    $bytes = [Convert]::FromBase64String($Base64)
    return (ConvertFrom-MrmPolicyTagBytes -Bytes $bytes)
}

function ConvertTo-MrmPolicyTagBase64 {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][Guid]$RetentionId)
    return [Convert]::ToBase64String($RetentionId.ToByteArray())
}

function ConvertFrom-MrmRetentionFlags {
    <# Decodes PidTagRetentionFlags integer to names, e.g. 8 -> 'PersonalTag'. #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][AllowNull()][Nullable[int]]$Flags)
    if ($null -eq $Flags) { return '' }
    if ($Flags -eq 0)     { return 'None' }
    # NB: OrderedDictionary treats an [int] indexer argument as POSITION, not key
    # (real bug caught by unit tests) - therefore enumerate entries instead.
    $names = foreach ($kv in $script:MrmRetentionFlagBits.GetEnumerator()) {
        if ($Flags -band [int]$kv.Key) { $kv.Value }
    }
    return ($names -join '|')
}

# ============================================================================
# Safety invariants
# ============================================================================

function Test-MrmTargetRetentionId {
    <# Throws if the requested target is protected or malformed.
       Returns the canonical lowercase GUID string. #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][string]$TargetRetentionId)
    $guid = [Guid]::Empty
    if (-not [Guid]::TryParse($TargetRetentionId, [ref]$guid)) {
        throw "TargetRetentionId '${TargetRetentionId}' is not a valid GUID."
    }
    $canon = $guid.ToString().ToLowerInvariant()
    if ($script:MrmProtectedRetentionIds -contains $canon) {
        throw "REFUSED: RetentionId ${canon} is on the protected list (e.g. 'Never Delete') and can never be a removal target."
    }
    if ($canon -eq [Guid]::Empty.ToString()) {
        throw "REFUSED: empty GUID is not a valid removal target."
    }
    return $canon
}

function Test-MrmWriteAllowed {
    <# THE hard invariant:
         if current physical PolicyTag RetentionId != target RetentionId -> NO WRITE.
       Pure function so it is unit-testable without EWS. #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)][AllowNull()][AllowEmptyString()][string]$CurrentRetentionId,
        [Parameter(Mandatory)][string]$TargetRetentionId
    )
    if ([string]::IsNullOrWhiteSpace($CurrentRetentionId)) { return $false }  # nothing stamped -> nothing to do
    $cur = $CurrentRetentionId.Trim().ToLowerInvariant()
    $tgt = (Test-MrmTargetRetentionId -TargetRetentionId $TargetRetentionId)
    if ($script:MrmProtectedRetentionIds -contains $cur) { return $false }    # belt & suspenders
    return ($cur -eq $tgt)
}

# ============================================================================
# OAuth (app-only) - client credentials, secret or certificate
# ============================================================================

#region Tenant report (multi-mailbox, read-only - improved ReportTagged.ps1)

function ConvertTo-MrmSafeFileName {
    <# UPN -> filesystem-safe stem (user@contoso.com -> user_at_contoso.com). #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][string]$Name)
    $n = $Name.Replace('@','_at_')
    return ([regex]::Replace($n, '[^A-Za-z0-9._\-]', '_'))
}

function Split-MrmMailboxList {
    <# Ergonomics: accepts ONE user, several comma/semicolon-separated users in
       one string, a real array, or any mix - returns a trimmed, deduplicated,
       order-preserving list. "a@x.com, b@x.com" and @('a@x.com','b@x.com')
       are equivalent. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyCollection()][string[]]$InputList)
    $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $out  = [System.Collections.Generic.List[string]]::new()
    foreach ($chunk in $InputList) {
        foreach ($m in ($chunk -split '[,;]')) {
            $t = $m.Trim()
            if ($t -and $seen.Add($t)) { $out.Add($t) }
        }
    }
    return $out
}

function Get-MrmGraphMailboxList {
    <# Tenant mailbox discovery via RAW Graph REST (no Microsoft.Graph module):
       GET /v1.0/users?$select=...&$top=999, follows @odata.nextLink, then
       filters client-side to users that actually have a mailbox (mail set).
       Requires Graph application permission User.Read.All (admin consented).
       Cheap on purpose: no per-user calls, one page = up to 999 users. #>
    [CmdletBinding()]
    param(
        [scriptblock]$TokenProvider,
        [scriptblock]$RequestHandler,
        [switch]$IncludeDisabled
    )
    $uri = 'https://graph.microsoft.com/v1.0/users?$select=userPrincipalName,mail,accountEnabled,userType&$top=999'
    $out = [System.Collections.Generic.List[object]]::new()
    while ($uri) {
        $page = Invoke-MrmGraphCall -Uri $uri -TokenProvider $TokenProvider -RequestHandler $RequestHandler
        foreach ($u in @($page.value)) {
            $mail = if ($u.PSObject.Properties['mail']) { $u.mail } else { $null }
            if (-not $mail) { continue }                                   # no mailbox
            $enabled = -not $u.PSObject.Properties['accountEnabled'] -or [bool]$u.accountEnabled
            if (-not $enabled -and -not $IncludeDisabled) { continue }
            $out.Add([pscustomobject]@{
                UserPrincipalName = $u.userPrincipalName
                Mail              = $mail
                AccountEnabled    = $enabled
                UserType          = $(if ($u.PSObject.Properties['userType']) { $u.userType } else { $null })
            })
        }
        $uri = if ($page.PSObject.Properties['@odata.nextLink']) { $page.'@odata.nextLink' } else { $null }
    }
    Write-MrmLog -Level Info -Message "Graph discovery: $($out.Count) mail-enabled users."
    # plain emit (0..n objects) - callers use @(...); the ,-wrap trick nests
    # empty arrays inside @(cmd) under some hosts (seen under Pester 6)
    return $out
}

function Get-MrmTenantTagRollup {
    <# Aggregates per-mailbox folder censuses into a tenant-wide view of every
       PHYSICALLY stamped retention tag (delete AND archive), the core
       physical-vs-effective distinction from gscales/ReportTagged.ps1 kept
       intact. Pure function - fully unit-testable. #>
    [CmdletBinding()]
    param(
        # records: census rows augmented with a Mailbox property
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Records
    )
    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($kind in 'Delete','Archive') {
        $idProp = if ($kind -eq 'Delete') { 'PolicyTagRetentionId' } else { 'ArchiveTagRetentionId' }
        $tagged = @($Records | Where-Object { $_.PSObject.Properties[$idProp] -and $_.$idProp })
        foreach ($g in ($tagged | Group-Object $idProp)) {
            $mbx     = @($g.Group | ForEach-Object { $_.Mailbox } | Sort-Object -Unique)
            $periods = @($g.Group | ForEach-Object { $_.RetentionPeriod } | Where-Object { $null -ne $_ } | Sort-Object -Unique)
            $flags   = @($g.Group | ForEach-Object { $_.RetentionFlagsDecoded } | Where-Object { $_ } | Sort-Object -Unique)
            $rows.Add([pscustomobject]@{
                Kind             = $kind
                RetentionId      = $g.Name
                FolderCount      = $g.Count
                MailboxCount     = $mbx.Count
                Mailboxes        = ($mbx | Select-Object -First 10) -join ';'
                PeriodsDays      = $periods -join ';'
                FlagsSeen        = $flags -join ' | '
                SamplePaths      = (@($g.Group | Select-Object -First 5 | ForEach-Object { $_.FolderPath }) -join ' ; ')
            })
        }
    }
    return @($rows | Sort-Object -Property @{e='FolderCount';Descending=$true})
}

#endregion

#region Tag-state backup (per-mailbox JSON safety net, fail-closed)

function Export-MrmTagStateBackup {
    <# Writes the per-mailbox SAFETY NET: one JSON file containing the complete
       physical tag state (delete AND archive stamps) of every stamped folder,
       plus a manifest header. This is the restore source - everything needed
       to re-stamp a folder by hand (FolderId, RetentionId, period, flags) is
       in here. Returns the file path. #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][string]$Mailbox,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Census,
        [Parameter(Mandatory)][string]$Directory,
        [string]$TargetRetentionId
    )
    New-Item -ItemType Directory -Force -Path $Directory | Out-Null
    $stamped = @($Census | Where-Object {
        ($_.PSObject.Properties['PolicyTagRetentionId']  -and $_.PolicyTagRetentionId) -or
        ($_.PSObject.Properties['ArchiveTagRetentionId'] -and $_.ArchiveTagRetentionId) })
    # never overwrite an earlier backup: millisecond stamp + collision suffix
    $path = Join-Path $Directory ("backup-tagstate-{0:yyyyMMdd-HHmmss-fff}.json" -f (Get-Date))
    $i = 1
    while (Test-Path $path) {
        $path = Join-Path $Directory ("backup-tagstate-{0:yyyyMMdd-HHmmss-fff}-{1}.json" -f (Get-Date), $i)
        $i++
    }
    [ordered]@{
        Schema            = 'mrm-tagstate-backup/1'
        Mailbox           = $Mailbox
        CapturedUtc       = [DateTime]::UtcNow.ToString('o')
        TargetRetentionId = $TargetRetentionId
        FoldersTotal      = @($Census).Count
        FoldersStamped    = $stamped.Count
        RestoreHint       = 'Re-stamp manually via EWS: $f.PolicyTag = [Microsoft.Exchange.WebServices.Data.PolicyTag]::new($true,[Guid]"<RetentionId>"); $f.Update() - deliberately not automated.'
        Folders           = $stamped
    } | ConvertTo-Json -Depth 8 | Set-Content -Path $path -Encoding UTF8
    return $path
}

function Test-MrmTagStateBackup {
    <# Fail-closed gate: re-reads the backup from disk and validates schema,
       mailbox and folder count. Only a $true from THIS function clears a
       mailbox for writes. #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Mailbox,
        [Parameter(Mandatory)][int]$ExpectedStampedCount
    )
    if (-not (Test-Path $Path)) { Write-MrmLog -Level Error -Message "Backup missing on disk: ${Path}"; return $false }
    try   { $b = Get-Content $Path -Raw -Encoding UTF8 | ConvertFrom-Json }
    catch { Write-MrmLog -Level Error -Message "Backup unreadable: ${Path} - $($_.Exception.Message)"; return $false }
    foreach ($chk in @(
        @{ ok = ($b.PSObject.Properties['Schema'] -and $b.Schema -eq 'mrm-tagstate-backup/1'); msg = 'schema mismatch' },
        @{ ok = ($b.PSObject.Properties['Mailbox'] -and $b.Mailbox -eq $Mailbox);              msg = 'mailbox mismatch' },
        @{ ok = ($b.PSObject.Properties['FoldersStamped'] -and [int]$b.FoldersStamped -eq $ExpectedStampedCount); msg = 'stamped-count mismatch' },
        @{ ok = ($ExpectedStampedCount -eq 0 -or @($b.Folders).Count -eq $ExpectedStampedCount); msg = 'folder-array count mismatch' }
    )) {
        if (-not $chk.ok) { Write-MrmLog -Level Error -Message "Backup validation failed (${Path}): $($chk.msg)"; return $false }
    }
    return $true
}

#endregion

#region Config (JSON, DPAPI secret handling - tokenhandler/Resend-GraphReplay ergonomics)

function Protect-MrmSecretString {
    <# SecureString -> encrypted standard string. On Windows this is DPAPI:
       bound to THIS user on THIS machine. On other platforms PowerShell falls
       back to an obfuscated (NOT cryptographically protected) encoding -
       treat configs as Windows-user-bound artifacts. #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][securestring]$Secret)
    return (ConvertFrom-SecureString -SecureString $Secret)
}

function Unprotect-MrmSecretString {
    <# Encrypted standard string (DPAPI) -> SecureString. Fails with a clear
       message when the blob was created by a different user/machine. #>
    [CmdletBinding()]
    [OutputType([securestring])]
    param([Parameter(Mandatory)][string]$Encrypted)
    try { return (ConvertTo-SecureString -String $Encrypted -ErrorAction Stop) }
    catch {
        throw ("Cannot decrypt secret from config: DPAPI blobs are bound to the " +
               "user+machine that created them. Re-run Manage-MrmConfig.ps1 -Action Encrypt " +
               "on THIS machine as THIS user. Inner: " + $_.Exception.Message)
    }
}

function Get-MrmConfig {
    <# Loads a JSON run config and resolves secrets:
         ClientSecretEncrypted        -> .ClientSecret        (SecureString)
         CertificatePasswordEncrypted -> .CertificatePassword (SecureString)
       A plaintext "ClientSecret" field is accepted but loudly discouraged. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path $Path)) { throw "Config not found: ${Path}" }
    $cfg = Get-Content $Path -Raw -Encoding UTF8 | ConvertFrom-Json

    $resolved = @{}
    foreach ($p in $cfg.PSObject.Properties) { $resolved[$p.Name] = $p.Value }

    if ($resolved.ContainsKey('ClientSecretEncrypted') -and $resolved['ClientSecretEncrypted']) {
        $resolved['ClientSecret'] = Unprotect-MrmSecretString -Encrypted $resolved['ClientSecretEncrypted']
    }
    elseif ($resolved.ContainsKey('ClientSecret') -and $resolved['ClientSecret'] -is [string] -and $resolved['ClientSecret']) {
        Write-MrmLog -Level Warning -Message "Config ${Path} stores a PLAINTEXT ClientSecret. Run Manage-MrmConfig.ps1 -Action Encrypt."
        $resolved['ClientSecret'] = ConvertTo-SecureString -String $resolved['ClientSecret'] -AsPlainText -Force
    }
    if ($resolved.ContainsKey('CertificatePasswordEncrypted') -and $resolved['CertificatePasswordEncrypted']) {
        $resolved['CertificatePassword'] = Unprotect-MrmSecretString -Encrypted $resolved['CertificatePasswordEncrypted']
    }
    return [pscustomobject]$resolved
}

function Resolve-MrmEffectiveSetting {
    <# CLI beats config: returns the bound CLI value when present, else the
       config value, else $null. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$BoundParameters,
        [Parameter(Mandatory)][object]$Config,
        [Parameter(Mandatory)][string]$Name
    )
    if ($BoundParameters.ContainsKey($Name)) { return $BoundParameters[$Name] }
    if ($Config.PSObject.Properties[$Name])  { return $Config.$Name }
    return $null
}

#endregion

function New-MrmClientAssertion {
    <# Builds a signed JWT client assertion (RS256) for certificate auth. #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][string]$TenantId,
        [Parameter(Mandatory)][string]$ClientId,
        [Parameter(Mandatory)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )
    if (-not $Certificate.HasPrivateKey) { throw "Certificate has no private key." }
    $b64url = { param($b) [Convert]::ToBase64String($b).TrimEnd('=').Replace('+','-').Replace('/','_') }
    $aud    = "https://login.microsoftonline.com/${TenantId}/oauth2/v2.0/token"
    $now    = [DateTimeOffset]::UtcNow
    $header = @{ alg = 'RS256'; typ = 'JWT'; x5t = (& $b64url $Certificate.GetCertHash()) } | ConvertTo-Json -Compress
    $claims = @{
        aud = $aud; iss = $ClientId; sub = $ClientId
        jti = [Guid]::NewGuid().ToString()
        nbf = $now.ToUnixTimeSeconds(); exp = $now.AddMinutes(10).ToUnixTimeSeconds()
    } | ConvertTo-Json -Compress
    $unsigned = (& $b64url ([Text.Encoding]::UTF8.GetBytes($header))) + '.' + (& $b64url ([Text.Encoding]::UTF8.GetBytes($claims)))
    $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Certificate)
    $sig = $rsa.SignData([Text.Encoding]::UTF8.GetBytes($unsigned),
        [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    return $unsigned + '.' + (& $b64url $sig)
}

function Get-MrmAccessToken {
    <#
    .SYNOPSIS
        App-only token via client credentials. Certificate preferred; secret supported.
        Caches per (ClientId|Scope) with a 5-minute expiry buffer.
    .NOTES
        EWS scope   : https://outlook.office365.com/.default
                      (Entra app permission: Office 365 Exchange Online -> full_access_as_app, admin consented)
        Graph scope : https://graph.microsoft.com/.default
                      (Graph application permission: Mail.ReadWrite)
        The token value is NEVER logged.
    #>
    [CmdletBinding(DefaultParameterSetName='Secret')]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][string]$TenantId,
        [Parameter(Mandatory)][string]$ClientId,
        [Parameter(Mandatory, ParameterSetName='Secret')][securestring]$ClientSecret,
        [Parameter(Mandatory, ParameterSetName='Certificate')]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [string]$Scope = 'https://outlook.office365.com/.default',
        [switch]$Force
    )
    $cacheKey = "${ClientId}|${Scope}"
    $cached = $script:MrmTokenCache[$cacheKey]
    if (-not $Force -and $cached -and $cached.ExpiresOn -gt (Get-Date).AddMinutes(5)) {
        return $cached.AccessToken
    }

    $tokenUrl = "https://login.microsoftonline.com/${TenantId}/oauth2/v2.0/token"
    $body = @{ client_id = $ClientId; scope = $Scope; grant_type = 'client_credentials' }

    if ($PSCmdlet.ParameterSetName -eq 'Certificate') {
        $body['client_assertion_type'] = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
        $body['client_assertion'] = New-MrmClientAssertion -TenantId $TenantId -ClientId $ClientId -Certificate $Certificate
        Write-MrmLog -Level Info -Message "Acquiring app-only token (certificate) for scope ${Scope}"
    }
    else {
        $plain = [System.Net.NetworkCredential]::new('', $ClientSecret).Password
        $body['client_secret'] = $plain
        Write-MrmLog -Level Info -Message "Acquiring app-only token (client secret) for scope ${Scope}"
    }

    try {
        $resp = Invoke-RestMethod -Method Post -Uri $tokenUrl -ContentType 'application/x-www-form-urlencoded' -Body $body
    }
    catch {
        # Do not echo the request body (it contains the secret/assertion).
        throw "Token acquisition failed for scope ${Scope}: $($_.Exception.Message)"
    }
    finally {
        if ($body.ContainsKey('client_secret'))    { $body['client_secret'] = $null }
        if ($body.ContainsKey('client_assertion')) { $body['client_assertion'] = $null }
    }

    $script:MrmTokenCache[$cacheKey] = [pscustomobject]@{
        AccessToken = $resp.access_token
        ExpiresOn   = (Get-Date).AddSeconds([int]$resp.expires_in)
    }
    Write-MrmLog -Level Info -Message "Token acquired; expires in $($resp.expires_in)s (value not logged)."
    return $resp.access_token
}

# ============================================================================
# EWS bootstrap
# ============================================================================

function Get-MrmEwsInstallPath {
    <# Where a machine-wide install of the EWS Managed API lives / should live.
       Preference order:
         1. official MSI location (Program Files) - if someone installed the
            EWS Managed API 2.2 MSI, use that, do not duplicate it
         2. machine-wide app dir  %ProgramData%\MRM-RetentionRepair\lib
         3. per-user app dir      %LOCALAPPDATA%\MRM-RetentionRepair\lib
            (used when the process is not elevated)
         4. repo-local lib\      (portable fallback, e.g. Linux/pwsh)
    #>
    [CmdletBinding()]
    [OutputType([object])]
    param([switch]$ForWrite)

    $msi = @(
        'C:\Program Files\Microsoft\Exchange\Web Services\2.2\Microsoft.Exchange.WebServices.dll',
        'C:\Program Files (x86)\Microsoft\Exchange\Web Services\2.2\Microsoft.Exchange.WebServices.dll'
    ) | Where-Object { Test-Path $_ } | Select-Object -First 1

    $isWin = ($PSVersionTable.PSVersion.Major -lt 6) -or $IsWindows
    $machine = if ($isWin -and $env:ProgramData)   { Join-Path $env:ProgramData  'MRM-RetentionRepair\lib' } else { $null }
    $user    = if ($isWin -and $env:LOCALAPPDATA)  { Join-Path $env:LOCALAPPDATA 'MRM-RetentionRepair\lib' } else { $null }
    $repo    = Join-Path $PSScriptRoot 'lib'

    $elevated = $false
    if ($isWin) {
        try {
            $id = [Security.Principal.WindowsIdentity]::GetCurrent()
            $elevated = ([Security.Principal.WindowsPrincipal]$id).IsInRole(
                [Security.Principal.WindowsBuiltInRole]::Administrator)
        } catch { $elevated = $false }
    }

    $writeDir = if ($ForWrite) {
        if ($machine -and $elevated) { $machine } elseif ($user) { $user } else { $repo }
    } else { $null }

    return [pscustomobject]@{
        MsiPath      = $msi
        MachineDir   = $machine
        UserDir      = $user
        RepoDir      = $repo
        IsElevated   = $elevated
        WriteDir     = $writeDir
        SearchOrder  = @($msi,
                         $(if ($machine) { Join-Path $machine 'Microsoft.Exchange.WebServices.dll' }),
                         $(if ($user)    { Join-Path $user    'Microsoft.Exchange.WebServices.dll' }),
                         (Join-Path $repo 'Microsoft.Exchange.WebServices.dll')) | Where-Object { $_ }
    }
}

function Install-MrmEwsManagedApi {
    <# Downloads Microsoft.Exchange.WebServices from NuGet and installs the
       net40 assembly into a stable location outside the repo (ProgramData when
       elevated, otherwise LocalAppData). Idempotent, version-pinned, unblocks
       the file and VERIFIES the assembly actually loads before returning. #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [string]$Version = '2.2.0',
        [string]$Destination,
        [switch]$Force
    )
    $paths = Get-MrmEwsInstallPath -ForWrite
    if (-not $Destination) { $Destination = $paths.WriteDir }

    if (-not $Force) {
        $existing = $paths.SearchOrder | Where-Object { Test-Path $_ } | Select-Object -First 1
        if ($existing) {
            Write-MrmLog -Level Info -Message "EWS Managed API already present: ${existing}"
            return $existing
        }
    }

    $dll = Join-Path $Destination 'Microsoft.Exchange.WebServices.dll'
    New-Item -ItemType Directory -Force -Path $Destination | Out-Null

    # Windows PowerShell 5.1 defaults to TLS 1.0/1.1; nuget.org requires 1.2.
    try {
        [Net.ServicePointManager]::SecurityProtocol =
            [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    } catch { }

    $uri = "https://www.nuget.org/api/v2/package/Microsoft.Exchange.WebServices/${Version}"
    # NB: Windows PowerShell 5.1's Expand-Archive REFUSES any extension other
    # than .zip ("'.nupkg' is not a supported archive file format"), while
    # pwsh 7 accepts it. A nupkg IS a zip, so download it with a .zip name.
    $pkg = Join-Path ([IO.Path]::GetTempPath()) ("Microsoft.Exchange.WebServices.${Version}.zip")
    $tmp = Join-Path ([IO.Path]::GetTempPath()) ("ewsnupkg_" + [Guid]::NewGuid().ToString('n'))
    Write-MrmLog -Level Info -Message "Downloading EWS Managed API ${Version} from nuget.org ..."
    Invoke-WebRequest -Uri $uri -OutFile $pkg -UseBasicParsing

    try {
        try {
            Expand-Archive -Path $pkg -DestinationPath $tmp -Force
        }
        catch {
            # Fallback for hosts where Expand-Archive is unavailable or picky
            Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
            [System.IO.Compression.ZipFile]::ExtractToDirectory($pkg, $tmp)
        }
        # nupkg layouts differ between versions - search instead of hardcoding
        $src = Get-ChildItem $tmp -Recurse -Filter 'Microsoft.Exchange.WebServices.dll' |
               Sort-Object { $_.FullName -notmatch '[\\/](40|net40)[\\/]' } |
               Select-Object -First 1
        if (-not $src) { throw "Package ${Version} contains no Microsoft.Exchange.WebServices.dll" }
        Copy-Item $src.FullName $dll -Force
        # the XML doc + Auth dll are optional but harmless to bring along
        foreach ($extra in @('Microsoft.Exchange.WebServices.Auth.dll')) {
            $e = Get-ChildItem $tmp -Recurse -Filter $extra -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($e) { Copy-Item $e.FullName (Join-Path $Destination $extra) -Force }
        }
    }
    finally {
        Remove-Item $pkg -Force -ErrorAction SilentlyContinue
        Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
    }

    try { if (Get-Command Unblock-File -ErrorAction SilentlyContinue) { Get-ChildItem "${Destination}\*.dll" | Unblock-File -ErrorAction SilentlyContinue } } catch { }

    $fi = Get-Item $dll
    if ($fi.Length -lt 100kb) { throw "Downloaded assembly looks wrong (size $($fi.Length) bytes): ${dll}" }
    $hash = try { (Get-FileHash -Path $dll -Algorithm MD5).Hash } catch { 'n/a' }
    Write-MrmLog -Level Info -Message "EWS Managed API ${Version} installed: ${dll} ($([Math]::Round($fi.Length/1kb)) KB, MD5 ${hash})"
    return $dll
}


function Import-MrmEwsAssembly {
    [CmdletBinding()]
    param([string]$Path)

    # Already loaded in THIS AppDomain? Then verify it is actually usable.
    # An assembly loaded from a byte[] has Location = '' and its
    # ExchangeServiceBase type initializer throws on first use - and it can
    # NEVER be unloaded, so the only cure is a fresh PowerShell session.
    $existing = 'Microsoft.Exchange.WebServices.Data.ExchangeService' -as [type]
    if ($existing) {
        $loc = ''
        try { $loc = $existing.Assembly.Location } catch { }
        $usable = $false
        try {
            $null = [Microsoft.Exchange.WebServices.Data.ExchangeService]::new(
                [Microsoft.Exchange.WebServices.Data.ExchangeVersion]::Exchange2013_SP1)
            $usable = $true
        } catch { $usable = $false }

        if ($usable) { return }

        throw (@(
            "An UNUSABLE Microsoft.Exchange.WebServices assembly is already loaded in this PowerShell session.",
            "  Assembly.Location : '${loc}'  (empty = loaded from memory, not from a file)",
            "  ExchangeService   : constructor throws (ExchangeServiceBase type initializer)",
            "A .NET assembly cannot be unloaded from a running process, so this session is",
            "permanently poisoned - most likely by an earlier failed load attempt.",
            "FIX: close this PowerShell window, open a NEW one, and re-run. The assembly",
            "will then be loaded from a real file path."
        ) -join [Environment]::NewLine)
    }
    if (-not $Path) {
        # Single source of truth for the search order (MSI > ProgramData >
        # LocalAppData > repo lib). A stale hardcoded list here previously put
        # the repo copy FIRST, which shadowed a freshly installed clean copy.
        $Path = (Get-MrmEwsInstallPath).SearchOrder | Where-Object { Test-Path $_ } | Select-Object -First 1
        if (-not $Path) {
            Write-MrmLog -Level Info -Message 'EWS Managed API not found locally - installing from nuget.org ...'
            $Path = Install-MrmEwsManagedApi
        }
    }
    $typeName = 'Microsoft.Exchange.WebServices.Data.ExchangeService'

    # The EWS Managed API MUST be loaded as a FILE. Its ExchangeServiceBase
    # static constructor reads Assembly.Location, so an assembly loaded from a
    # byte[] (Location = "") throws TypeInitializationException on the first
    # ExchangeService ctor. Byte-loading "works" for Add-Type and then breaks
    # at the first real call - so we never do it.
    $tried = [System.Collections.Generic.List[string]]::new()

    # Candidates: the requested path first, then everything else we know about.
    $candidates = @($Path) + @((Get-MrmEwsInstallPath).SearchOrder | Where-Object { $_ -ne $Path })
    $candidates = @($candidates | Where-Object { $_ -and (Test-Path $_) })

    $lastErr = $null
    foreach ($c in $candidates) {
        try { if (Get-Command Unblock-File -ErrorAction SilentlyContinue) { Unblock-File -Path $c -ErrorAction SilentlyContinue } } catch { }
        try { Add-Type -Path $c -ErrorAction Stop } catch { $lastErr = $_ }
        if ($typeName -as [type]) { $Path = $c; break }
        $tried.Add($c)

        # Zone.Identifier that survived Unblock-File (GPO, locked ADS, folder
        # extracted from a ZIP): copy to a fresh temp file - a new file has no
        # mark-of-the-web - and load THAT as a file, keeping Assembly.Location.
        try {
            $shadow = Join-Path ([IO.Path]::GetTempPath()) ("mrm-ews-" + [Guid]::NewGuid().ToString('n'))
            New-Item -ItemType Directory -Force -Path $shadow | Out-Null
            # Mirror the WHOLE directory, not just the main DLL: sibling
            # assemblies (Microsoft.Exchange.WebServices.Auth.dll) must stay
            # next to it or the CLR cannot probe for them.
            Copy-Item -Path (Join-Path (Split-Path $c -Parent) '*.dll') -Destination $shadow -Force
            $copy = Join-Path $shadow 'Microsoft.Exchange.WebServices.dll'
            if (-not (Test-Path $copy)) { Copy-Item -LiteralPath $c -Destination $copy -Force }
            try { if (Get-Command Unblock-File -ErrorAction SilentlyContinue) { Get-ChildItem (Join-Path $shadow '*.dll') | Unblock-File -ErrorAction SilentlyContinue } } catch { }
            Add-Type -Path $copy -ErrorAction Stop
            if ($typeName -as [type]) {
                Write-MrmLog -Level Warning -Message "Loading was blocked for ${c}; loaded a clean shadow copy from ${copy} instead."
                $Path = $copy
                break
            }
        } catch { $lastErr = $_ }

        # Third file-based route: load it as a binary module. Import-Module uses
        # Assembly.LoadFrom, a different load context than Add-Type's
        # LoadFile - some hosts accept one and reject the other.
        try {
            Import-Module -Name $c -ErrorAction Stop -DisableNameChecking
            if ($typeName -as [type]) {
                Write-MrmLog -Level Warning -Message "Add-Type did not work for ${c}; loaded it as a binary module (Import-Module) instead."
                $Path = $c
                break
            }
        } catch { $lastErr = $_ }
    }

    if (-not ($typeName -as [type])) {
        $sizes = foreach ($t in $tried) { "  ${t} ($((Get-Item $t -ErrorAction SilentlyContinue).Length) bytes)" }
        $hint = @(
            "EWS Managed API could not be loaded. Tried:",
            ($sizes -join [Environment]::NewLine),
            "Expected size for 2.2.0: 1130264 bytes, MD5 98CB0EF1ECBB683D0DA19A17B5739F25",
            "Diagnose:",
            "    (Get-FileHash '<path>' -Algorithm MD5).Hash",
            "    Get-Item '<path>' -Stream * | Select-Object Stream",
            "Fix - install a clean copy outside the repo and remove the repo copy:",
            "    Import-Module .\MRM-RetentionRepair.psm1 -Force",
            "    Install-MrmEwsManagedApi -Force",
            "    Remove-Item .\lib\Microsoft.Exchange.WebServices.dll"
        ) -join [Environment]::NewLine
        if ($lastErr) { $hint += [Environment]::NewLine + "Inner error: $($lastErr.Exception.Message)" }
        throw $hint
    }

    # Proof, not assumption: the type must also be CONSTRUCTIBLE. A byte-loaded
    # or half-broken assembly resolves the type but throws here.
    try {
        $probe = [Microsoft.Exchange.WebServices.Data.ExchangeService]::new(
            [Microsoft.Exchange.WebServices.Data.ExchangeVersion]::Exchange2013_SP1)
        if ($null -eq $probe) { throw 'ExchangeService ctor returned null.' }
    }
    catch {
        throw ("EWS assembly loaded from ${Path} but ExchangeService could not be constructed: " +
               "$($_.Exception.Message). This usually means the assembly was loaded without a " +
               "file location. Run Install-MrmEwsManagedApi -Force and remove the repo-local copy.")
    }
    # Optional companion assembly. The main DLL does NOT statically reference it
    # (verified via GetReferencedAssemblies), so this is best-effort only and a
    # failure here must never break the load.
    $auth = Join-Path (Split-Path $Path -Parent) 'Microsoft.Exchange.WebServices.Auth.dll'
    if ((Test-Path $auth) -and -not ('Microsoft.Exchange.WebServices.Auth.Validation.AuthValidator' -as [type])) {
        try {
            if (Get-Command Unblock-File -ErrorAction SilentlyContinue) { Unblock-File -Path $auth -ErrorAction SilentlyContinue }
            Add-Type -Path $auth -ErrorAction Stop
            Write-MrmLog -Level Info -Message "Loaded companion assembly: ${auth}"
        } catch {
            Write-MrmLog -Level Debug -Message "Companion Auth.dll not loaded (not required): $($_.Exception.Message)"
        }
    }
    Write-MrmLog -Level Info -Message "Loaded EWS Managed API from ${Path} (type resolved)."
}

function Connect-MrmEwsService {
    <# Explicit EXO endpoint (no Autodiscover), OAuth, app-only impersonation. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Mailbox,
        [Parameter(Mandatory)][string]$AccessToken
    )
    Import-MrmEwsAssembly
    $service = [Microsoft.Exchange.WebServices.Data.ExchangeService]::new(
        [Microsoft.Exchange.WebServices.Data.ExchangeVersion]::Exchange2013_SP1)
    $service.Url = [Uri]'https://outlook.office365.com/EWS/Exchange.asmx'
    $service.Credentials = [Microsoft.Exchange.WebServices.Data.OAuthCredentials]::new($AccessToken)
    $service.ImpersonatedUserId = [Microsoft.Exchange.WebServices.Data.ImpersonatedUserId]::new(
        [Microsoft.Exchange.WebServices.Data.ConnectingIdType]::SmtpAddress, $Mailbox)
    $service.HttpHeaders.Add('X-AnchorMailbox', $Mailbox)
    $service.UserAgent = 'MRM-RetentionRepair/1.0'
    if ($null -eq $service -or $null -eq $service.Url) {
        throw "EWS service object could not be constructed for ${Mailbox} - refusing to continue with a null service."
    }
    return $service
}

function Get-MrmEwsPropertyDefinitions {
    [CmdletBinding()]
    param()
    Import-MrmEwsAssembly
    $B = [Microsoft.Exchange.WebServices.Data.MapiPropertyType]::Binary
    $I = [Microsoft.Exchange.WebServices.Data.MapiPropertyType]::Integer
    $S = [Microsoft.Exchange.WebServices.Data.MapiPropertyType]::String
    return @{
        PolicyTag       = [Microsoft.Exchange.WebServices.Data.ExtendedPropertyDefinition]::new(0x3019, $B)
        RetentionPeriod = [Microsoft.Exchange.WebServices.Data.ExtendedPropertyDefinition]::new(0x301A, $I)
        RetentionFlags  = [Microsoft.Exchange.WebServices.Data.ExtendedPropertyDefinition]::new(0x301D, $I)
        ArchiveTag      = [Microsoft.Exchange.WebServices.Data.ExtendedPropertyDefinition]::new(0x3018, $B)
        FolderPath      = [Microsoft.Exchange.WebServices.Data.ExtendedPropertyDefinition]::new(0x66B5, $S)
    }
}

function ConvertTo-MrmFolderPath {
    <# 0x66B5 uses U+FFFE as separator; normalize to '/segment/segment'. #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$RawPath)
    $sep = [string][char]0xFFFE
    $p = $RawPath.Replace($sep, '/')
    if (-not $p.StartsWith('/')) { $p = '/' + $p }
    return $p
}

# ============================================================================
# Phase 1A - read-only physical-tag census
# ============================================================================

function Get-MrmFolderCensus {
    <#
    .SYNOPSIS
        Deep-enumerates all folders under MsgFolderRoot with paging and returns
        one record per folder including the RAW physical MAPI retention state.
        READ-ONLY. Additionally runs Glen Scales' Exists(PR_POLICY_TAG) filtered
        search as an independent cross-check of the physical-stamp count.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Service,
        [int]$PageSize = 1000
    )
    $props = Get-MrmEwsPropertyDefinitions
    $ps = [Microsoft.Exchange.WebServices.Data.PropertySet]::new(
        [Microsoft.Exchange.WebServices.Data.BasePropertySet]::IdOnly,
        [Microsoft.Exchange.WebServices.Data.FolderSchema]::DisplayName,
        [Microsoft.Exchange.WebServices.Data.FolderSchema]::ParentFolderId,
        [Microsoft.Exchange.WebServices.Data.FolderSchema]::TotalCount,
        [Microsoft.Exchange.WebServices.Data.FolderSchema]::FolderClass,
        [Microsoft.Exchange.WebServices.Data.FolderSchema]::PolicyTag,
        [Microsoft.Exchange.WebServices.Data.FolderSchema]::ArchiveTag)
    $ps.Add($props.PolicyTag); $ps.Add($props.RetentionPeriod)
    $ps.Add($props.RetentionFlags); $ps.Add($props.ArchiveTag); $ps.Add($props.FolderPath)

    $root = [Microsoft.Exchange.WebServices.Data.FolderId]::new(
        [Microsoft.Exchange.WebServices.Data.WellKnownFolderName]::MsgFolderRoot)

    $view = [Microsoft.Exchange.WebServices.Data.FolderView]::new($PageSize, 0)
    $view.Traversal = [Microsoft.Exchange.WebServices.Data.FolderTraversal]::Deep
    $view.PropertySet = $ps

    $records = [System.Collections.Generic.List[object]]::new()
    do {
        $page = $Service.FindFolders($root, $view)
        foreach ($f in $page.Folders) {
            $records.Add((ConvertTo-MrmCensusRecord -Folder $f -Props $props))
        }
        $view.Offset += $page.Folders.Count
    } while ($page.MoreAvailable)

    # Independent cross-check: physically stamped folders via Exists(PR_POLICY_TAG)
    $view2 = [Microsoft.Exchange.WebServices.Data.FolderView]::new($PageSize, 0)
    $view2.Traversal = [Microsoft.Exchange.WebServices.Data.FolderTraversal]::Deep
    $view2.PropertySet = [Microsoft.Exchange.WebServices.Data.PropertySet]::new(
        [Microsoft.Exchange.WebServices.Data.BasePropertySet]::IdOnly)
    $exists = [Microsoft.Exchange.WebServices.Data.SearchFilter+Exists]::new($props.PolicyTag)
    $physicalIds = [System.Collections.Generic.HashSet[string]]::new()
    do {
        $page2 = $Service.FindFolders($root, $exists, $view2)
        foreach ($f in $page2.Folders) { [void]$physicalIds.Add($f.Id.UniqueId) }
        $view2.Offset += $page2.Folders.Count
    } while ($page2.MoreAvailable)

    foreach ($r in $records) {
        $r.ExistsFilterHit = $physicalIds.Contains($r.FolderId)
        if ($r.HasPhysicalPolicyTag -ne $r.ExistsFilterHit) {
            Write-MrmLog -Level Warning -Message "Census/Exists mismatch on '$($r.FolderPath)' - HasPhysicalPolicyTag=$($r.HasPhysicalPolicyTag) ExistsFilterHit=$($r.ExistsFilterHit)"
        }
    }
    return $records
}

function ConvertTo-MrmCensusRecord {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Folder, [Parameter(Mandatory)]$Props)

    $rawPolicy = $null; $rawArchive = $null; $period = $null; $flags = $null; $rawPath = $null
    [void]$Folder.TryGetProperty($Props.PolicyTag,       [ref]$rawPolicy)
    [void]$Folder.TryGetProperty($Props.ArchiveTag,      [ref]$rawArchive)
    [void]$Folder.TryGetProperty($Props.RetentionPeriod, [ref]$period)
    [void]$Folder.TryGetProperty($Props.RetentionFlags,  [ref]$flags)
    [void]$Folder.TryGetProperty($Props.FolderPath,      [ref]$rawPath)

    $policyGuid  = if ($rawPolicy)  { ConvertFrom-MrmPolicyTagBytes -Bytes $rawPolicy }  else { $null }
    $archiveGuid = if ($rawArchive) { ConvertFrom-MrmPolicyTagBytes -Bytes $rawArchive } else { $null }

    # First-class EWS properties (typed view of the same physical state)
    $fcPolicy = $null; $fcArchive = $null
    try { if ($Folder.PolicyTag)  { $fcPolicy  = $Folder.PolicyTag.RetentionId.ToString().ToLowerInvariant() } } catch { }
    try { if ($Folder.ArchiveTag) { $fcArchive = $Folder.ArchiveTag.RetentionId.ToString().ToLowerInvariant() } } catch { }

    $path = if ($rawPath) { ConvertTo-MrmFolderPath -RawPath $rawPath } else { '/' + $Folder.DisplayName }

    [pscustomobject]@{
        FolderPath             = $path
        DisplayName            = $Folder.DisplayName
        FolderId               = $Folder.Id.UniqueId
        ParentFolderId         = if ($Folder.ParentFolderId) { $Folder.ParentFolderId.UniqueId } else { $null }
        FolderClass            = $Folder.FolderClass
        ItemCount              = $Folder.TotalCount
        HasPhysicalPolicyTag   = [bool]$rawPolicy
        PolicyTagRetentionId   = $policyGuid
        PolicyTagFirstClass    = $fcPolicy
        RetentionPeriod        = $period
        RetentionFlagsRaw      = $flags
        RetentionFlagsDecoded  = ConvertFrom-MrmRetentionFlags -Flags $flags
        HasPhysicalArchiveTag  = [bool]$rawArchive
        ArchiveTagRetentionId  = $archiveGuid
        ArchiveTagFirstClass   = $fcArchive
        ExistsFilterHit        = $null   # filled by Get-MrmFolderCensus cross-check
    }
}

function Get-MrmCensusSummary {
    <# The falsifier. Prints the ACTUAL physical count - does not force A or B. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object[]]$Census,
        [Parameter(Mandatory)][string]$TargetRetentionId,
        [Nullable[int]]$KnownEffectiveCount   # e.g. 261 from Get-MailboxFolderStatistics (external)
    )
    $tgt = (Test-MrmTargetRetentionId -TargetRetentionId $TargetRetentionId)
    $physicalAll    = @($Census | Where-Object HasPhysicalPolicyTag)
    $physicalTarget = @($physicalAll | Where-Object { $_.PolicyTagRetentionId -eq $tgt })
    $physicalOther  = @($physicalAll | Where-Object { $_.PolicyTagRetentionId -ne $tgt })
    $existsCount    = @($Census | Where-Object ExistsFilterHit).Count

    $conclusion =
        if ($null -eq $KnownEffectiveCount) {
            "Physical target stamps: $($physicalTarget.Count). No external effective count supplied for comparison."
        }
        elseif ($physicalTarget.Count -lt $KnownEffectiveCount) {
            "RESULT A-shaped: $($physicalTarget.Count) physical stamps vs ${KnownEffectiveCount} effective folders - inheritance/materialization centered on stamped roots."
        }
        elseif ($physicalTarget.Count -eq $KnownEffectiveCount) {
            "RESULT B-shaped: physical stamps ($($physicalTarget.Count)) equal effective folders (${KnownEffectiveCount}) - tag materialized on every affected folder."
        }
        else {
            "RESULT C: $($physicalTarget.Count) physical stamps EXCEED the ${KnownEffectiveCount} effective folders. Evidence contradicts both hypotheses - inspect before proceeding."
        }

    [pscustomobject]@{
        FoldersScanned              = $Census.Count
        PhysicalPolicyTagFolders    = $physicalAll.Count
        ExistsFilterFolders         = $existsCount
        PhysicalTargetTagFolders    = $physicalTarget.Count
        PhysicalOtherPolicyTags     = $physicalOther.Count
        OtherPolicyTagIds           = @($physicalOther | ForEach-Object { $_.PolicyTagRetentionId } | Sort-Object -Unique)
        KnownEffectiveTargetFolders = $KnownEffectiveCount
        TargetRetentionId           = $tgt
        Conclusion                  = $conclusion
        PhysicalTargetFolderPaths   = @($physicalTarget | ForEach-Object { $_.FolderPath } | Sort-Object)
    }
}

# ============================================================================
# Phase 1B - item-level audit (read-only)
# ============================================================================

function Get-MrmItemAudit {
    <#
    .SYNOPSIS
        Bounded, read-only audit of items PHYSICALLY carrying PR_POLICY_TAG in
        the given folders. Answers: are items stamped, or only inheriting?
        Never dumps bodies. Subjects only with -IncludeSubjects.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Service,
        [Parameter(Mandatory)][object[]]$Folders,       # census records
        [int]$MaxItemsPerFolder = 2000,
        [int]$PageSize = 500,
        [switch]$IncludeSubjects
    )
    Import-MrmEwsAssembly
    $props = Get-MrmEwsPropertyDefinitions
    $ps = [Microsoft.Exchange.WebServices.Data.PropertySet]::new(
        [Microsoft.Exchange.WebServices.Data.BasePropertySet]::IdOnly,
        [Microsoft.Exchange.WebServices.Data.ItemSchema]::DateTimeReceived,
        [Microsoft.Exchange.WebServices.Data.ItemSchema]::DateTimeCreated)
    if ($IncludeSubjects) { $ps.Add([Microsoft.Exchange.WebServices.Data.ItemSchema]::Subject) }
    $ps.Add($props.PolicyTag); $ps.Add($props.RetentionPeriod); $ps.Add($props.RetentionFlags)

    $existsItemTag = [Microsoft.Exchange.WebServices.Data.SearchFilter+Exists]::new($props.PolicyTag)
    $results = [System.Collections.Generic.List[object]]::new()

    foreach ($folder in $Folders) {
        $fid = [Microsoft.Exchange.WebServices.Data.FolderId]::new($folder.FolderId)
        $view = [Microsoft.Exchange.WebServices.Data.ItemView]::new($PageSize, 0)
        $view.PropertySet = $ps
        $collected = 0
        do {
            $page = Invoke-MrmEwsWithRetry { $Service.FindItems($fid, $existsItemTag, $view) }
            foreach ($item in $page.Items) {
                $raw = $null; $per = $null; $flg = $null
                [void]$item.TryGetProperty($props.PolicyTag,       [ref]$raw)
                [void]$item.TryGetProperty($props.RetentionPeriod, [ref]$per)
                [void]$item.TryGetProperty($props.RetentionFlags,  [ref]$flg)
                $results.Add([pscustomobject]@{
                    FolderPath            = $folder.FolderPath
                    ItemId                = $item.Id.UniqueId
                    Subject               = if ($IncludeSubjects) { $item.Subject } else { $null }
                    PolicyTagRetentionId  = if ($raw) { ConvertFrom-MrmPolicyTagBytes -Bytes $raw } else { $null }
                    RetentionFlagsRaw     = $flg
                    RetentionFlagsDecoded = ConvertFrom-MrmRetentionFlags -Flags $flg
                    RetentionPeriod       = $per
                    DateTimeReceived      = $item.DateTimeReceived
                    DateTimeCreated       = $item.DateTimeCreated
                })
                $collected++
                if ($collected -ge $MaxItemsPerFolder) { break }
            }
            $view.Offset += $page.Items.Count
        } while ($page.MoreAvailable -and $collected -lt $MaxItemsPerFolder)

        Write-MrmLog -Level Info -Message "Item audit '$($folder.FolderPath)': physically tagged items sampled=${collected} (cap ${MaxItemsPerFolder}), folder claims TotalCount=$($folder.ItemCount)"
    }
    return $results
}

function Invoke-MrmEwsWithRetry {
    <# Retries EWS ServerBusy / transient faults with bounded exponential backoff. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][scriptblock]$Operation,
        [int]$MaxRetries = 5
    )
    $attempt = 0
    while ($true) {
        try { return (& $Operation) }
        catch {
            $attempt++
            $msg = $_.Exception.Message
            $sbType = 'Microsoft.Exchange.WebServices.Data.ServerBusyException' -as [type]
            $isSb   = ($sbType -and $sbType.IsInstanceOfType($_.Exception))
            $isBusy = $isSb -or ($msg -match 'ServerBusy|too busy|throttl|429|503')
            if (-not $isBusy -or $attempt -gt $MaxRetries) { throw }
            $delayMs = if ($isSb) { [Math]::Max($_.Exception.BackOffMilliseconds, 1000) }
                       else       { [Math]::Min(60000, 1000 * [Math]::Pow(2, $attempt)) }
            Write-MrmLog -Level Warning -Message "EWS throttled/transient (attempt ${attempt}/${MaxRetries}); backing off $([int]$delayMs)ms"
            Start-Sleep -Milliseconds $delayMs
        }
    }
}

# ============================================================================
# Phase 1C - safe folder untag (dry-run default)
# ============================================================================

function Get-MrmFolderRawState {
    <# Re-binds a folder and captures the FULL physical + first-class retention state. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Service,
        [Parameter(Mandatory)][string]$FolderId
    )
    $props = Get-MrmEwsPropertyDefinitions
    $ps = [Microsoft.Exchange.WebServices.Data.PropertySet]::new(
        [Microsoft.Exchange.WebServices.Data.BasePropertySet]::IdOnly,
        [Microsoft.Exchange.WebServices.Data.FolderSchema]::DisplayName,
        [Microsoft.Exchange.WebServices.Data.FolderSchema]::PolicyTag,
        [Microsoft.Exchange.WebServices.Data.FolderSchema]::ArchiveTag)
    $ps.Add($props.PolicyTag); $ps.Add($props.RetentionPeriod)
    $ps.Add($props.RetentionFlags); $ps.Add($props.ArchiveTag); $ps.Add($props.FolderPath)

    $fid = [Microsoft.Exchange.WebServices.Data.FolderId]::new($FolderId)
    $f = Invoke-MrmEwsWithRetry { [Microsoft.Exchange.WebServices.Data.Folder]::Bind($Service, $fid, $ps) }
    $rec = ConvertTo-MrmCensusRecord -Folder $f -Props $props
    $rec | Add-Member -NotePropertyName CapturedUtc -NotePropertyValue ([DateTime]::UtcNow.ToString('o'))
    return $rec
}

function Invoke-MrmFolderUntag {
    <#
    .SYNOPSIS
        Surgically removes the physical PolicyTag from folders whose CURRENT
        physical RetentionId equals -TargetRetentionId. Uses the NATIVE EWS
        semantic (folder.PolicyTag = $null; folder.Update()) - no manual
        deletion of 0x3019/0x301A/0x301D. What the native operation does to
        those raw properties is CAPTURED as evidence, not assumed.

        DRY-RUN BY DEFAULT. Writes require BOTH -Apply and ShouldProcess
        confirmation (-WhatIf is honored). Idempotent: a second -Apply run
        finds no matching physical tag and performs zero writes.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact='High')]
    param(
        [Parameter(Mandatory)][AllowNull()]$Service,
        [Parameter(Mandatory)][object[]]$Census,
        [Parameter(Mandatory)][string]$TargetRetentionId,
        [switch]$Apply,
        [Parameter(Mandatory)][string]$SnapshotDirectory,
        [string]$LogPath
    )
    Import-MrmEwsAssembly
    $tgt = Test-MrmTargetRetentionId -TargetRetentionId $TargetRetentionId
    New-Item -ItemType Directory -Force -Path $SnapshotDirectory | Out-Null
    $jsonl = Join-Path $SnapshotDirectory ("untag-changes-{0:yyyyMMdd-HHmmss}.jsonl" -f (Get-Date))

    $candidates = @($Census | Where-Object { $_.HasPhysicalPolicyTag -and $_.PolicyTagRetentionId -eq $tgt })
    $skippedOther = @($Census | Where-Object { $_.HasPhysicalPolicyTag -and $_.PolicyTagRetentionId -ne $tgt })

    Write-MrmLog -LogPath $LogPath -Level Info -Message "Untag candidates (physical RetentionId == target): $($candidates.Count)"
    foreach ($s in $skippedOther) {
        Write-MrmLog -LogPath $LogPath -Level Info -Message "PROTECTED/SKIPPED (non-matching physical tag $($s.PolicyTagRetentionId)): $($s.FolderPath)"
    }

    if (-not $Apply) {
        Write-MrmLog -LogPath $LogPath -Level Warning -Message "MODE: AUDIT ONLY - NO CHANGES MADE. Re-run with -Apply to mutate."
        return [pscustomobject]@{ Mode='AuditOnly'; Candidates=$candidates; Changed=@(); Skipped=$skippedOther }
    }

    if ($null -eq $Service) { throw 'Apply mode requires a connected EWS service.' }
    $changed = [System.Collections.Generic.List[object]]::new()
    foreach ($c in $candidates) {
        # Re-verify LIVE state immediately before write - the census may be stale
        # and the folder may have changed or disappeared.
        try {
            $before = Get-MrmFolderRawState -Service $Service -FolderId $c.FolderId
        }
        catch {
            Write-MrmLog -LogPath $LogPath -Level Warning -Message "Folder vanished/unreadable since audit, skipping: $($c.FolderPath) - $($_.Exception.Message)"
            continue
        }

        if (-not (Test-MrmWriteAllowed -CurrentRetentionId $before.PolicyTagRetentionId -TargetRetentionId $tgt)) {
            Write-MrmLog -LogPath $LogPath -Level Warning -Message "Live state no longer matches target (now '$($before.PolicyTagRetentionId)'), NO WRITE: $($c.FolderPath)"
            continue
        }

        if (-not $PSCmdlet.ShouldProcess($c.FolderPath, "Remove physical PolicyTag ${tgt} (native EWS PolicyTag=null)")) {
            continue
        }

        Write-MrmLog -LogPath $LogPath -Level Change -Message "UNTAG: $($c.FolderPath)"
        $fid = [Microsoft.Exchange.WebServices.Data.FolderId]::new($c.FolderId)
        $folder = Invoke-MrmEwsWithRetry { [Microsoft.Exchange.WebServices.Data.Folder]::Bind($Service, $fid) }

        # Final in-object guard on the typed property as well.
        if (-not $folder.PolicyTag -or $folder.PolicyTag.RetentionId.ToString().ToLowerInvariant() -ne $tgt) {
            Write-MrmLog -LogPath $LogPath -Level Warning -Message "Bound folder no longer carries target tag, NO WRITE: $($c.FolderPath)"
            continue
        }

        $folder.PolicyTag = $null            # native EWS semantic - the oracle behavior
        Invoke-MrmEwsWithRetry { $folder.Update() } | Out-Null

        $after = Get-MrmFolderRawState -Service $Service -FolderId $c.FolderId
        $record = [pscustomobject]@{
            TimestampUtc = [DateTime]::UtcNow.ToString('o')
            Action       = 'PolicyTagNull'
            Target       = $tgt
            FolderPath   = $c.FolderPath
            FolderId     = $c.FolderId
            Before       = $before
            After        = $after
            Verified     = (-not $after.HasPhysicalPolicyTag) -and ($null -eq $after.PolicyTagFirstClass)
        }
        ($record | ConvertTo-Json -Depth 6 -Compress) | Add-Content -Path $jsonl -Encoding utf8
        $changed.Add($record)

        if ($record.Verified) {
            Write-MrmLog -LogPath $LogPath -Level Change -Message "VERIFIED clean: $($c.FolderPath) | after 0x3019=$($after.HasPhysicalPolicyTag) 0x301A=$($after.RetentionPeriod) 0x301D=$($after.RetentionFlagsRaw) ($($after.RetentionFlagsDecoded))"
        } else {
            Write-MrmLog -LogPath $LogPath -Level Error -Message "POST-WRITE STATE UNEXPECTED on $($c.FolderPath) - PolicyTag still present. STOP and inspect ${jsonl}"
            break
        }
    }
    return [pscustomobject]@{ Mode='Apply'; Candidates=$candidates; Changed=$changed; Skipped=$skippedOther; ChangeLog=$jsonl }
}

# ============================================================================
# Evidence snapshots
# ============================================================================

function Export-MrmEvidence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object[]]$Records,
        [Parameter(Mandatory)][string]$OutputDirectory,
        [Parameter(Mandatory)][string]$BaseName
    )
    New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $csv  = Join-Path $OutputDirectory "${BaseName}-${stamp}.csv"
    $json = Join-Path $OutputDirectory "${BaseName}-${stamp}.json"
    $Records | Export-Csv -Path $csv -NoTypeInformation -Encoding utf8
    $Records | ConvertTo-Json -Depth 6 | Set-Content -Path $json -Encoding utf8
    Write-MrmLog -Level Info -Message "Evidence written: ${csv} and ${json}"
    return [pscustomobject]@{ Csv = $csv; Json = $json }
}

# ============================================================================
# PHASE 2 - Microsoft Graph (read parity; write experiment gated)
# ============================================================================

function Invoke-MrmGraphRequest {
    <# Raw Graph REST with bounded retry: 429 honors Retry-After, 5xx uses
       exponential backoff, 401 refreshes the token once via -TokenProvider.
       Never logs the Authorization header. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Uri,
        [string]$Method = 'GET',
        [object]$Body,
        [Parameter(Mandatory)][scriptblock]$TokenProvider,
        [int]$MaxRetries = 6
    )
    $attempt = 0
    $refreshed = $false
    while ($true) {
        $headers = @{ Authorization = "Bearer $(& $TokenProvider)" }
        try {
            $splat = @{ Method = $Method; Uri = $Uri; Headers = $headers; ContentType = 'application/json' }
            if ($null -ne $Body) { $splat.Body = ($Body | ConvertTo-Json -Depth 10) }
            return Invoke-RestMethod @splat
        }
        catch {
            $status = $null
            try { $status = [int]$_.Exception.Response.StatusCode } catch { }
            $attempt++
            if ($status -eq 401 -and -not $refreshed) {
                $refreshed = $true
                Write-MrmLog -Level Warning -Message "Graph 401 - refreshing token once and retrying."
                & $TokenProvider -Force | Out-Null
                continue
            }
            if ($status -eq 429 -and $attempt -le $MaxRetries) {
                $ra = 30
                # PS 5.1: HttpWebResponse -> WebHeaderCollection['Retry-After']
                # PS 7  : HttpResponseMessage -> Headers.GetValues('Retry-After')
                try { $h = $_.Exception.Response.Headers['Retry-After']; if ($h) { $ra = [int]$h } } catch { }
                try { $v = $_.Exception.Response.Headers.GetValues('Retry-After') | Select-Object -First 1; if ($v) { $ra = [int]$v } } catch { }
                $ra = [Math]::Min([Math]::Max($ra,1), 300)
                Write-MrmLog -Level Warning -Message "Graph 429 - honoring Retry-After=${ra}s (attempt ${attempt}/${MaxRetries})"
                Start-Sleep -Seconds $ra
                continue
            }
            if ($status -ge 500 -and $status -le 599 -and $attempt -le $MaxRetries) {
                $wait = [Math]::Min(60, [Math]::Pow(2, $attempt))
                Write-MrmLog -Level Warning -Message "Graph ${status} - backoff $([int]$wait)s (attempt ${attempt}/${MaxRetries})"
                Start-Sleep -Seconds $wait
                continue
            }
            throw "Graph request failed (${Method} ${Uri}) status=${status}: $($_.Exception.Message)"
        }
    }
}

function Invoke-MrmGraphCall {
    <# Routes a Graph call through either the built-in raw-token client
       (Invoke-MrmGraphRequest, oldschool) or a caller-supplied handler
       (e.g. Microsoft.Graph SDK's Invoke-MgGraphRequest). #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Uri,
        [string]$Method = 'GET',
        [object]$Body,
        [scriptblock]$TokenProvider,
        [scriptblock]$RequestHandler
    )
    if ($RequestHandler) { return (& $RequestHandler $Uri $Method $Body) }
    if (-not $TokenProvider) { throw 'Either -TokenProvider or -RequestHandler is required.' }
    return Invoke-MrmGraphRequest -Uri $Uri -Method $Method -Body $Body -TokenProvider $TokenProvider
}

function Get-MrmGraphFolderCensus {
    <#
    .SYNOPSIS
        Recursively enumerates /users/{upn}/mailFolders (v1.0), reading the same
        legacy extended properties:
            Binary  0x3019, Integer 0x301A, Integer 0x301D, Binary 0x3018
        Handles @odata.nextLink paging at every level. READ-ONLY.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Mailbox,
        [scriptblock]$TokenProvider,
        [scriptblock]$RequestHandler,
        [switch]$IncludeHidden
    )
    $expand = "singleValueExtendedProperties(`$filter=id eq 'Binary 0x3019' or id eq 'Integer 0x301a' or id eq 'Integer 0x301d' or id eq 'Binary 0x3018')"
    $base = "https://graph.microsoft.com/v1.0/users/$([uri]::EscapeDataString($Mailbox))/mailFolders"
    $hidden = if ($IncludeHidden) { '&includeHiddenFolders=true' } else { '' }
    $records = [System.Collections.Generic.List[object]]::new()

    $walk = $null
    $walk = {
        param([string]$Uri, [string]$ParentPath)
        $next = $Uri
        while ($next) {
            $page = Invoke-MrmGraphCall -Uri $next -TokenProvider $TokenProvider -RequestHandler $RequestHandler
            foreach ($f in $page.value) {
                $path = "${ParentPath}/$($f.displayName)"
                $rec = ConvertTo-MrmGraphCensusRecord -GraphFolder $f -FolderPath $path
                $records.Add($rec)
                if ($f.childFolderCount -gt 0) {
                    $childUri = "${base}/$($f.id)/childFolders?`$top=100&`$expand=${expand}${hidden}"
                    & $walk $childUri $path
                }
            }
            $next = if ($page.PSObject.Properties['@odata.nextLink']) { $page.'@odata.nextLink' } else { $null }
        }
    }
    & $walk "${base}?`$top=100&`$expand=${expand}${hidden}" ''
    return $records
}

function ConvertTo-MrmGraphCensusRecord {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$GraphFolder, [Parameter(Mandatory)][string]$FolderPath)
    $policyB64 = $null; $archiveB64 = $null; $period = $null; $flags = $null
    $svep = $null
    if ($GraphFolder.PSObject.Properties['singleValueExtendedProperties']) {
        $svep = $GraphFolder.singleValueExtendedProperties
    }
    foreach ($p in @($svep)) {
        if ($null -eq $p) { continue }
        switch -Regex ($p.id) {
            '(?i)Binary 0x3019'  { $policyB64  = $p.value }
            '(?i)Binary 0x3018'  { $archiveB64 = $p.value }
            '(?i)Integer 0x301a' { $period     = [int]$p.value }
            '(?i)Integer 0x301d' { $flags      = [int]$p.value }
        }
    }
    [pscustomobject]@{
        FolderPath            = $FolderPath
        DisplayName           = $GraphFolder.displayName
        GraphFolderId         = $GraphFolder.id
        ItemCount             = $GraphFolder.totalItemCount
        HasPhysicalPolicyTag  = [bool]$policyB64
        PolicyTagRetentionId  = if ($policyB64)  { ConvertFrom-MrmPolicyTagBase64 -Base64 $policyB64 }  else { $null }
        PolicyTagBase64       = $policyB64
        RetentionPeriod       = $period
        RetentionFlagsRaw     = $flags
        RetentionFlagsDecoded = ConvertFrom-MrmRetentionFlags -Flags $flags
        HasPhysicalArchiveTag = [bool]$archiveB64
        ArchiveTagRetentionId = if ($archiveB64) { ConvertFrom-MrmPolicyTagBase64 -Base64 $archiveB64 } else { $null }
    }
}

function Compare-MrmCensusParity {
    <# EWS is the oracle. Compares by normalized FolderPath. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object[]]$EwsCensus,
        [Parameter(Mandatory)][object[]]$GraphCensus,
        [Parameter(Mandatory)][string]$TargetRetentionId
    )
    $tgt = Test-MrmTargetRetentionId -TargetRetentionId $TargetRetentionId
    $ewsMap   = @{}; foreach ($e in $EwsCensus)   { $ewsMap[$e.FolderPath]   = $e }
    $graphMap = @{}; foreach ($g in $GraphCensus) { $graphMap[$g.FolderPath] = $g }

    $missingInGraph = [System.Collections.Generic.List[object]]::new()
    $mismatches     = [System.Collections.Generic.List[object]]::new()
    $matched        = 0

    foreach ($path in $ewsMap.Keys) {
        $e = $ewsMap[$path]
        if (-not $graphMap.ContainsKey($path)) {
            if ($e.HasPhysicalPolicyTag) { $missingInGraph.Add($e) }
            continue
        }
        $g = $graphMap[$path]
        $same = ($e.HasPhysicalPolicyTag -eq $g.HasPhysicalPolicyTag) -and
                ($e.PolicyTagRetentionId -eq $g.PolicyTagRetentionId) -and
                (($e.RetentionPeriod    -as [string]) -eq ($g.RetentionPeriod -as [string])) -and
                (($e.RetentionFlagsRaw  -as [string]) -eq ($g.RetentionFlagsRaw -as [string]))
        if ($same) { $matched++ }
        else {
            $mismatches.Add([pscustomobject]@{
                FolderPath = $path
                EwsPolicy = $e.PolicyTagRetentionId; GraphPolicy = $g.PolicyTagRetentionId
                EwsPeriod = $e.RetentionPeriod;      GraphPeriod = $g.RetentionPeriod
                EwsFlags  = $e.RetentionFlagsRaw;    GraphFlags  = $g.RetentionFlagsRaw
            })
        }
    }
    $extraInGraph = @($graphMap.Keys | Where-Object { -not $ewsMap.ContainsKey($_) -and $graphMap[$_].HasPhysicalPolicyTag })

    $ewsTargets   = @($EwsCensus   | Where-Object { $_.PolicyTagRetentionId -eq $tgt }).Count
    $graphTargets = @($GraphCensus | Where-Object { $_.PolicyTagRetentionId -eq $tgt }).Count

    [pscustomobject]@{
        EwsPhysicalTargetFolders   = $ewsTargets
        GraphPhysicalTargetFolders = $graphTargets
        Matched                    = $matched
        MissingInGraph             = $missingInGraph.Count
        ExtraInGraph               = $extraInGraph.Count
        PropertyMismatches         = $mismatches.Count
        MissingInGraphPaths        = @($missingInGraph | ForEach-Object { $_.FolderPath })
        ExtraInGraphPaths          = $extraInGraph
        MismatchDetails            = $mismatches
        ParityOk                   = ($missingInGraph.Count -eq 0 -and $mismatches.Count -eq 0 -and $ewsTargets -eq $graphTargets)
    }
}

function Get-MrmGraphItemAudit {
    <# Read-only Graph item audit for one folder - parity counterpart of 1B. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Mailbox,
        [Parameter(Mandatory)][string]$GraphFolderId,
        [scriptblock]$TokenProvider,
        [int]$MaxItems = 2000
    )
    $expand = "singleValueExtendedProperties(`$filter=id eq 'Binary 0x3019' or id eq 'Integer 0x301a' or id eq 'Integer 0x301d')"
    $filter = "singleValueExtendedProperties/any(ep: ep/id eq 'Binary 0x3019' and ep/value ne null)"
    $uri = "https://graph.microsoft.com/v1.0/users/$([uri]::EscapeDataString($Mailbox))/mailFolders/${GraphFolderId}/messages?`$top=100&`$select=id,receivedDateTime&`$expand=${expand}&`$filter=$([uri]::EscapeDataString($filter))"
    $out = [System.Collections.Generic.List[object]]::new()
    while ($uri -and $out.Count -lt $MaxItems) {
        $page = Invoke-MrmGraphCall -Uri $uri -TokenProvider $TokenProvider -RequestHandler $RequestHandler
        foreach ($m in $page.value) {
            $b64 = $null; $per = $null; $flg = $null
            foreach ($p in @($m.singleValueExtendedProperties)) {
                if ($null -eq $p) { continue }
                switch -Regex ($p.id) {
                    '(?i)Binary 0x3019'  { $b64 = $p.value }
                    '(?i)Integer 0x301a' { $per = [int]$p.value }
                    '(?i)Integer 0x301d' { $flg = [int]$p.value }
                }
            }
            $out.Add([pscustomobject]@{
                ItemId = $m.id
                PolicyTagRetentionId  = if ($b64) { ConvertFrom-MrmPolicyTagBase64 -Base64 $b64 } else { $null }
                RetentionPeriod       = $per
                RetentionFlagsRaw     = $flg
                RetentionFlagsDecoded = ConvertFrom-MrmRetentionFlags -Flags $flg
                ReceivedDateTime      = $m.receivedDateTime
            })
            if ($out.Count -ge $MaxItems) { break }
        }
        $uri = if ($page.PSObject.Properties['@odata.nextLink']) { $page.'@odata.nextLink' } else { $null }
    }
    return $out
}

function Invoke-MrmGraphWriteProbe {
    <#
    .SYNOPSIS
        PHASE 2B - controlled write EXPERIMENT on exactly ONE disposable test
        folder. Graph v1.0 documents PATCHing singleValueLegacyExtendedProperties
        but documents NO delete operation for them. We therefore DO NOT assume
        any encoding of "remove". This probe:
          1. captures Graph raw state (caller must also capture EWS raw state),
          2. attempts ONE documented PATCH variant,
          3. re-reads Graph state,
          4. tells the operator to re-read via EWS and compare against the
             tests/fixtures/ews-policytag-null-after.json contract.
        It never runs against a folder still carrying the target on live data
        paths unless the operator names it explicitly, and it refuses to run
        without -IUnderstandThisIsAnExperiment.

        DEFAULT PROJECT POSITION until proven:
          READ/AUDIT parity  : supported
          WRITE/UNTAG parity : NOT PROVEN - EWS remains the mutation path.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact='High')]
    param(
        [Parameter(Mandatory)][string]$Mailbox,
        [Parameter(Mandatory)][string]$GraphFolderId,
        [scriptblock]$TokenProvider,
        [ValidateSet('EmptyStringValue')][string]$Variant = 'EmptyStringValue',
        [switch]$IUnderstandThisIsAnExperiment
    )
    if (-not $IUnderstandThisIsAnExperiment) {
        throw "REFUSED: Graph write parity is unproven. Pass -IUnderstandThisIsAnExperiment and target ONE disposable test folder only. EWS remains the supported mutation path."
    }
    $uri = "https://graph.microsoft.com/v1.0/users/$([uri]::EscapeDataString($Mailbox))/mailFolders/${GraphFolderId}?`$expand=singleValueExtendedProperties(`$filter=id eq 'Binary 0x3019' or id eq 'Integer 0x301a' or id eq 'Integer 0x301d')"
    $before = Invoke-MrmGraphCall -Uri $uri -TokenProvider $TokenProvider -RequestHandler $RequestHandler

    if (-not $PSCmdlet.ShouldProcess($GraphFolderId, "Graph write probe variant '${Variant}'")) { return }

    switch ($Variant) {
        'EmptyStringValue' {
            # The only documented mutation surface: PATCH the folder with a
            # singleValueExtendedProperties collection. Whether value:"" clears,
            # zeroes, or rejects is EXACTLY what this experiment measures.
            $body = @{ singleValueExtendedProperties = @(@{ id = 'Binary 0x3019'; value = '' }) }
            $probeResult = $null
            $probeError  = $null
            try {
                $probeResult = Invoke-MrmGraphCall -Uri "https://graph.microsoft.com/v1.0/users/$([uri]::EscapeDataString($Mailbox))/mailFolders/${GraphFolderId}" -Method PATCH -Body $body -TokenProvider $TokenProvider -RequestHandler $RequestHandler
            } catch { $probeError = $_.Exception.Message }
        }
    }

    $after = Invoke-MrmGraphCall -Uri $uri -TokenProvider $TokenProvider -RequestHandler $RequestHandler
    [pscustomobject]@{
        Variant     = $Variant
        Before      = $before
        After       = $after
        ProbeError  = $probeError
        NextStep    = 'Re-read the SAME folder via EWS (Get-MrmFolderRawState) and diff against tests/fixtures/ews-policytag-null-after.json. Graph write parity counts as proven ONLY if EWS confirms identical absence/state.'
    }
}

Export-ModuleMember -Function @(
    'Protect-MrmLogText','Write-MrmLog',
    'ConvertFrom-MrmPolicyTagBytes','ConvertTo-MrmPolicyTagBytes',
    'ConvertFrom-MrmPolicyTagBase64','ConvertTo-MrmPolicyTagBase64',
    'ConvertFrom-MrmRetentionFlags','ConvertTo-MrmFolderPath',
    'Test-MrmTargetRetentionId','Test-MrmWriteAllowed',
    'New-MrmClientAssertion','Get-MrmAccessToken',
    'Install-MrmEwsManagedApi','Get-MrmEwsInstallPath','Import-MrmEwsAssembly','Connect-MrmEwsService',
    'Get-MrmEwsPropertyDefinitions','Get-MrmFolderCensus','ConvertTo-MrmCensusRecord',
    'Get-MrmCensusSummary','Get-MrmItemAudit','Invoke-MrmEwsWithRetry',
    'Get-MrmFolderRawState','Invoke-MrmFolderUntag','Export-MrmEvidence',
    'Invoke-MrmGraphRequest','Invoke-MrmGraphCall','Protect-MrmSecretString','Unprotect-MrmSecretString','Get-MrmConfig','Resolve-MrmEffectiveSetting','ConvertTo-MrmSafeFileName','Get-MrmGraphMailboxList','Get-MrmTenantTagRollup','Split-MrmMailboxList','Export-MrmTagStateBackup','Test-MrmTagStateBackup','Get-MrmGraphFolderCensus','ConvertTo-MrmGraphCensusRecord',
    'Compare-MrmCensusParity','Get-MrmGraphItemAudit','Invoke-MrmGraphWriteProbe'
)
