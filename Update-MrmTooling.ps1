#Requires -Version 5.1
<#
.SYNOPSIS
Updates the MRM-RetentionRepair tooling in place - no manual ZIP downloads.

.DESCRIPTION
Two routes, picked automatically:
  * git present and this is a clone  -> git pull (fast-forward only)
  * otherwise                        -> download the zipball from GitHub and
                                        replace the tool files

NEVER touched by an update:
    configs\      your run configs (tenant ids + DPAPI secret blobs)
    evidence\     audit output, backups, JSONL change logs
    lib\          the EWS assembly
Everything else is replaced by the repo version. Local edits to tool files are
backed up to  .backup\<timestamp>\  before they are overwritten.

Prints the commit SHA it moved to, so a run is always attributable.

.EXAMPLE
    ./Update-MrmTooling.ps1
.EXAMPLE
    ./Update-MrmTooling.ps1 -WhatIf          # show what would change
    ./Update-MrmTooling.ps1 -Ref v1.2        # pin to a tag/branch/commit
    ./Update-MrmTooling.ps1 -Force           # discard local tool-file edits
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$Repository = 'PSScript/MRM-RetentionRepair',
    [string]$Ref        = 'main',
    [string]$Destination = $PSScriptRoot,
    [switch]$Force,
    [switch]$UseZip     # skip git even when available
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Windows PowerShell 5.1 still negotiates TLS 1.0/1.1 by default; GitHub refuses.
try {
    [Net.ServicePointManager]::SecurityProtocol =
        [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
} catch { }

$PreservePaths = @('configs', 'evidence', 'lib', '.backup')

function Write-Step { param([string]$Text) Write-Host $Text -ForegroundColor Cyan }
function Write-Ok   { param([string]$Text) Write-Host "  [ok] $Text" -ForegroundColor Green }
function Write-Warn { param([string]$Text) Write-Host "  [!]  $Text" -ForegroundColor Yellow }

Write-Step "MRM-RetentionRepair updater"
Write-Host  "  Repository : ${Repository}"
Write-Host  "  Ref        : ${Ref}"
Write-Host  "  Destination: ${Destination}"
Write-Host  ""

$hasGit   = [bool](Get-Command git -ErrorAction SilentlyContinue)
$isClone  = Test-Path (Join-Path $Destination '.git')
$useGit   = $hasGit -and $isClone -and -not $UseZip

# ---------------------------------------------------------------- git route --
if ($useGit) {
    Write-Step "Route: git"
    Push-Location $Destination
    try {
        $dirty = @(git status --porcelain --untracked-files=no 2>$null)
        if ($dirty -and -not $Force) {
            Write-Warn "Local modifications to tracked files:"
            $dirty | ForEach-Object { Write-Host "       $_" }
            Write-Warn "Re-run with -Force to discard them, or commit/stash first."
            return
        }
        if ($dirty -and $Force) {
            if ($PSCmdlet.ShouldProcess($Destination, 'git checkout -- . (discard local edits)')) {
                git checkout -- . 2>&1 | Out-Null
                Write-Ok "Discarded local edits."
            }
        }
        $before = (git rev-parse --short HEAD 2>$null)
        if ($PSCmdlet.ShouldProcess("${Repository}#${Ref}", 'git pull --ff-only')) {
            git fetch --quiet origin $Ref 2>&1 | Out-Null
            $out = git merge --ff-only "origin/${Ref}" 2>&1
            if ($LASTEXITCODE -ne 0) {
                Write-Warn "Fast-forward not possible: ${out}"
                Write-Warn "Your local history diverged. Use -UseZip for a clean overwrite,"
                Write-Warn "or resolve it with git manually."
                return
            }
        }
        $after = (git rev-parse --short HEAD 2>$null)
        if ($before -eq $after) { Write-Ok "Already up to date (${after})." }
        else {
            Write-Ok "Updated ${before} -> ${after}"
            git --no-pager log --oneline "${before}..${after}" 2>$null |
                ForEach-Object { Write-Host "       $_" }
        }
    }
    finally { Pop-Location }
}
# ---------------------------------------------------------------- zip route --
else {
    Write-Step "Route: zipball (git $(if ($hasGit) { 'available but this is not a clone' } else { 'not installed' }))"

    $api = "https://api.github.com/repos/${Repository}/commits/${Ref}"
    $sha = $null
    try {
        $commit = Invoke-RestMethod -Uri $api -UseBasicParsing -Headers @{ 'User-Agent' = 'MRM-RetentionRepair-Updater' }
        $sha = $commit.sha.Substring(0,7)
        Write-Ok "Remote ${Ref} is at ${sha} ($($commit.commit.message.Split("`n")[0]))"
    }
    catch { Write-Warn "Could not read commit metadata: $($_.Exception.Message)" }

    $zip = Join-Path ([IO.Path]::GetTempPath()) ("mrm-update-{0}.zip" -f ([Guid]::NewGuid().ToString('n')))
    $tmp = Join-Path ([IO.Path]::GetTempPath()) ("mrm-update-{0}"     -f ([Guid]::NewGuid().ToString('n')))
    try {
        Write-Step "Downloading ..."
        Invoke-WebRequest -Uri "https://github.com/${Repository}/archive/refs/heads/${Ref}.zip" `
                          -OutFile $zip -UseBasicParsing
        # NB: 5.1's Expand-Archive only accepts .zip - hence the extension above.
        try { Expand-Archive -Path $zip -DestinationPath $tmp -Force }
        catch {
            Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
            [System.IO.Compression.ZipFile]::ExtractToDirectory($zip, $tmp)
        }
        $root = Get-ChildItem $tmp -Directory | Select-Object -First 1
        if (-not $root) { throw "Downloaded archive has no root directory." }

        $incoming = Get-ChildItem $root.FullName -Recurse -File
        $backupDir = Join-Path $Destination (".backup\{0:yyyyMMdd-HHmmss}" -f (Get-Date))
        $changed = 0; $added = 0; $skipped = 0

        foreach ($src in $incoming) {
            $rel = $src.FullName.Substring($root.FullName.Length).TrimStart('\','/')
            $top = ($rel -split '[\\/]')[0]
            if ($PreservePaths -contains $top) { $skipped++; continue }

            $dst = Join-Path $Destination $rel
            $exists = Test-Path $dst
            if ($exists) {
                $same = (Get-FileHash $src.FullName -Algorithm SHA256).Hash -eq
                        (Get-FileHash $dst          -Algorithm SHA256).Hash
                if ($same) { continue }
            }

            if ($PSCmdlet.ShouldProcess($rel, $(if ($exists) { 'replace' } else { 'add' }))) {
                if ($exists) {
                    $bkp = Join-Path $backupDir $rel
                    New-Item -ItemType Directory -Force -Path (Split-Path $bkp -Parent) | Out-Null
                    Copy-Item $dst $bkp -Force
                    $changed++
                } else { $added++ }
                New-Item -ItemType Directory -Force -Path (Split-Path $dst -Parent) | Out-Null
                Copy-Item $src.FullName $dst -Force
            }
        }

        Write-Host ""
        Write-Ok "Replaced: ${changed}   Added: ${added}   Preserved (configs/evidence/lib): ${skipped}"
        if ($changed -gt 0) { Write-Ok "Backup of replaced files: ${backupDir}" }
        if ($sha) { Write-Ok "Now at ${Repository}@${sha}" }
    }
    finally {
        Remove-Item $zip -Force -ErrorAction SilentlyContinue
        Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# ------------------------------------------------------------------ verify ---
Write-Host ""
Write-Step "Verifying"
$psFiles = Get-ChildItem $Destination -Include '*.ps1','*.psm1' -Recurse |
           Where-Object { $_.FullName -notmatch '[\\/](lib|\.backup)[\\/]' }
$bad = @()
foreach ($f in $psFiles) {
    $errs = $null
    [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$null, [ref]$errs) | Out-Null
    if ($errs) { $bad += "$($f.Name): $($errs[0].Message)" }
}
if ($bad) {
    Write-Warn "Files with parse errors:"
    $bad | ForEach-Object { Write-Host "       $_" -ForegroundColor Red }
} else {
    Write-Ok "$($psFiles.Count) script files parse cleanly."
}

Write-Host ""
Write-Host "IMPORTANT: if an EWS assembly was already loaded in this session, close" -ForegroundColor Yellow
Write-Host "this PowerShell window and open a new one - .NET assemblies cannot be"   -ForegroundColor Yellow
Write-Host "unloaded, so an updated module still runs against the old assembly."     -ForegroundColor Yellow
