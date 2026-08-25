# MRM-RetentionRepair

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

Run tests:  pwsh -c "Invoke-Pester -Path ./tests"
Start here: docs/RUNBOOK.md
References: PSScript/tokenhandler (throttling/token patterns),
            PSScript/Resend-GraphReplay (client_credentials + 429 handling)
