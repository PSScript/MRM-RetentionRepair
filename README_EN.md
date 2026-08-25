# MRM-RetentionRepair

*(Deutsche Version: [README.md](README.md))*

Safe, evidence-driven audit + surgical removal of one bad classic Exchange
Online MRM Personal retention tag from a mailbox. Two strict phases:
EWS Managed API 2.2 (OAuth, oracle) → Microsoft Graph (read parity; write
experiment gated & unproven by default).

    MRM-RetentionRepair/
      MRM-RetentionRepair.psm1        core module (30 exported functions)
      Invoke-MrmRetentionAudit.ps1    Phase 1A/1B — read-only census + item audit
      Invoke-MrmRetentionRepair.ps1   Phase 1C   — dry-run default, -Apply gated
      Invoke-MrmGraphParity.ps1       Phase 2A/2B — token-based ("oldschool"): raw
                                       client_credentials + Invoke-RestMethod,
                                       ZERO module dependencies (tokenhandler-style)
      Invoke-MrmTenantTagReport.ps1   tenant-wide READ-ONLY report of physically
                                       stamped retention tags across mailboxes —
                                       modernized ReportTagged.ps1 (gscales),
                                       deliberately without the Mg module
      Invoke-MrmTenantTagRepair.ps1   tenant-wide nulling of ONE physical
                                       PolicyTag across many mailboxes —
                                       DryRun (default) -> -TestRun (capped)
                                       -> -Apply; per-folder evidence cell
                                       READ -> BACKUP -> SET -> READ -> COMPARE
      Invoke-MrmGraphParity.Mg.ps1    Phase 2A/2B — Microsoft.Graph SDK variant:
                                       Connect-MgGraph / Invoke-MgGraphRequest
                                       (requires only Microsoft.Graph.Authentication)
      lib/                             EWS Managed API 2.2 (NuGet, net40; loads in pwsh7)
      tests/                           Pester suite (33 tests) + fixtures
      docs/RUNBOOK.md                  operator runbook, gates, EWS retirement notes

Compatibility
-------------
- Windows PowerShell 5.1 AND PowerShell 7+ (PSScriptAnalyzer
  PSUseCompatibleSyntax targets 5.1/7.0: clean; all files carry a UTF-8 BOM so
  5.1 does not misread non-ASCII as ANSI).
- Retry-After is read via BOTH header APIs (WebHeaderCollection indexer for
  5.1's HttpWebResponse, GetValues for 7's HttpResponseMessage) — same dual
  pattern as PSScript/tokenhandler.
- Two Graph client variants, same module, same evidence format:
  * token-based (default, no modules)  -> Invoke-MrmGraphParity.ps1
  * Microsoft.Graph SDK                -> Invoke-MrmGraphParity.Mg.ps1
- EWS phase is always raw-OAuth (EWS Managed API 2.2 DLL, auto-fetched from
  NuGet by Install-MrmEwsManagedApi or shipped in lib/).
- Tests: Pester 5+/6 under pwsh (note: a Describe name must not contain "<->" —
  Pester 6.1.0 escaped-flow-control bug).


Updating without ZIP juggling
-----------------------------
`./Update-MrmTooling.ps1` - uses `git pull` when this is a clone, otherwise the
GitHub zipball. `-WhatIf` previews, `-Force` discards local tool-file edits,
`-Ref` pins a tag/branch/commit. First install into an empty folder:

       iwr "https://raw.githubusercontent.com/PSScript/MRM-RetentionRepair/main/Update-MrmTooling.ps1" -OutFile .\Update-MrmTooling.ps1 -UseBasicParsing; .\Update-MrmTooling.ps1 -UseZip

`configs\`, `evidence\` and `lib\` are never overwritten; replaced tool files
are backed up under `.backup\<timestamp>\` first. All scripts are parse-checked
after the update.

Usage (quickstart)
------------------
1. **Create a config** (interactive; secrets prompted hidden and stored
   DPAPI-encrypted — bound to user+machine):

       ./Manage-MrmConfig.ps1 -Action Create -ConfigPath ./configs/TENANT-A.json
       ./Manage-MrmConfig.ps1 -Action Test   -ConfigPath ./configs/TENANT-A.json   # required fields + EWS/Graph tokens
       ./Manage-MrmConfig.ps1 -Action Show   -ConfigPath ./configs/TENANT-A.json   # secrets masked

   An editable template ships in the repo:
   [`configs/TENANT-EXAMPLE.template.json`](configs/TENANT-EXAMPLE.template.json)
   — copy it to `configs/<NAME>.json`, fill in the values, then run
   `-Action Encrypt` for the secret. More examples:
   [docs/Config-Examples.md](docs/Config-Examples.md).
   CLI parameters override config values; config overrides script defaults.

2. **Gates 1-4 — read-only audit**:   `./Invoke-MrmRetentionAudit.ps1 -ConfigPath ./configs/TENANT-A.json -IncludeItemAudit`
3. **Gate 5 — pilot** (ONE folder):   `./Invoke-MrmRetentionRepair.ps1 -ConfigPath ./configs/TENANT-A.json -Apply -PilotFolderPath '/Archive/Projects/ProjectB' -CaptureFixture`
4. **Gate 6 — bulk** (dry-run default): `./Invoke-MrmRetentionRepair.ps1 -ConfigPath ./configs/TENANT-A.json -Apply`
5. **Gate 7 — Graph read parity**:    `./Invoke-MrmGraphParity.ps1 -ConfigPath ./configs/TENANT-A.json -EwsCensusJson ./evidence/folder-census-<ts>.json` (or `.Mg.ps1`)
6. **Gate 8 — write experiment** (disposable folder, double-gated): add `-ExperimentalWriteProbe -ProbeGraphFolderId <id> -IUnderstandThisIsAnExperiment`

Gates, ordering (restore BEFORE MFA!) and rollback limits: [docs/RUNBOOK.md](docs/RUNBOOK.md).

**Tenant report** (read-only, independent of the gates):
`./Invoke-MrmTenantTagReport.ps1 -ConfigPath ./configs/TENANT-A.json -MailboxCsv ./mailboxes.csv [-FilterRetentionId <guid>] [-Resume]`
or discovery via raw Graph REST (app permission User.Read.All, no Mg module): add `-DiscoverViaGraph`.
Outputs per-mailbox JSON, a consolidated CSV and a tenant rollup (RetentionIds x folders x mailboxes x periods x flags). Physical stamps only (Exists 0x3019/0x3018), as in the original.

**Tenant repair** (nulling the tag across mailboxes — deliberately slow learning curve):
mailbox mode 1 = one user / comma-separated / array (`-Mailbox 'a@c.com,b@c.com'`), mode 2 = `-AllMailboxes` (raw Graph discovery, no Mg).
Stages: DryRun (default, zero writes) -> `-TestRun` (writes, capped to 1 mailbox x 1 folder by default) -> `-Apply` (full). `-TestRun` and `-Apply` are mutually exclusive.
Per-mailbox safety net under `evidence/tenant-repair/logging/<mbx>/`: a complete tag-state backup (`backup-tagstate-*.json`, schema `mrm-tagstate-backup/1`) is written AND read back before any write — fail-closed: no verified backup, no writes in that mailbox. Every mutation additionally runs READ -> BACKUP (JSONL) -> SET (native PolicyTag=null) -> READ -> COMPARE (Verified); an unexpected post-write state stops that mailbox. Pre/post censuses + backups per mailbox under evidence/tenant-repair/<mbx>/.

Prerequisite: EWS Managed API
-----------------------------
`./Install-MrmPrerequisites.ps1` downloads Microsoft.Exchange.WebServices from
nuget.org, installs it outside the repo (official MSI install > `%ProgramData%\MRM-RetentionRepair\lib`
when elevated > `%LOCALAPPDATA%\...` > repo `lib\`), unblocks it and verifies
every required type resolves. `-WhatIfPathsOnly` shows the search order without
touching anything. At runtime the same order is searched and a missing assembly
is installed automatically.

Windows gotcha
--------------
If the EWS DLL fails to load (`FileLoadException`, HRESULT 0x80131515) it is
zone-blocked: `Get-ChildItem .\lib\*.dll | Unblock-File`. The tool now
unblocks proactively, verifies the type resolves before claiming success, and
treats a zero-folder census as a failure rather than a clean mailbox.

Run tests:  pwsh -c "Invoke-Pester -Path ./tests"
Start here: docs/RUNBOOK.md
References: PSScript/tokenhandler (throttling/token patterns),
            PSScript/Resend-GraphReplay (client_credentials + 429 handling)
