# MRM-RetentionRepair — Runbook

Incident tooling: surgical removal of ONE mailbox-local physical MRM Personal
retention tag (`PR_POLICY_TAG` = `d94993b5-e987-4275-8707-072057cfb2b8`,
"6 Month Delete") after an unintended MFA deletion event.
**EWS is the behavioral oracle. Graph must reproduce EWS-proven behavior, never
an assumed interpretation of MAPI documentation.**

---

## 1. EWS app registration (Phase 1)

1. Entra ID → App registration (or reuse a dedicated incident app).
2. API permissions → **APIs my organization uses → Office 365 Exchange Online**
   → Application permissions → **`full_access_as_app`** → **admin consent**.
3. **Certificate authentication preferred.** Upload the public cert to the app;
   keep the private key in the operator machine store (`Cert:\CurrentUser\My`)
   or a PFX. Client secret is supported (`-ClientSecret`) but discouraged.
4. Token scope: `https://outlook.office365.com/.default` (client credentials).
5. Strongly recommended: scope the app to the affected mailbox via an
   ApplicationAccessPolicy (done in EXO by the operator, outside this tool):
   `New-ApplicationAccessPolicy -AppId <id> -PolicyScopeGroupId <mail-enabled SG> -AccessRight RestrictAccess`
6. The tool uses the **explicit endpoint** `https://outlook.office365.com/EWS/Exchange.asmx`
   — no Autodiscover, no Basic Auth, ever.

## 2. EWS retirement context (why this is temporary)

- EWS in Exchange Online still works **now** with OAuth app-only tokens.
- Microsoft begins **blocking EWS for non-allow-listed apps in October 2026**
  (retirement wave; tenant/app exceptions via allow-listing only, and time-boxed).
- Therefore: this EWS implementation is a **temporary oracle and repair tool**
  for this incident window — not long-term architecture. The Graph parity work
  (Phase 2) exists precisely to establish (or honestly refuse) a successor path.
- Verify the current allow-list/retirement state in Microsoft's EWS retirement
  announcements before relying on this tool after Q3 2026.

## 2b. Two Graph client variants

| | `Invoke-MrmGraphParity.ps1` (default) | `Invoke-MrmGraphParity.Mg.ps1` |
|---|---|---|
| Auth | raw `client_credentials` POST (cert-JWT or secret), token cached with 5-min buffer | `Connect-MgGraph` app-only |
| HTTP | `Invoke-RestMethod` + own 429/5xx/401 retry | `Invoke-MgGraphRequest` (SDK retry) |
| Dependencies | none | `Microsoft.Graph.Authentication` |
| Lineage | PSScript/tokenhandler, Resend-GraphReplay | Microsoft Graph SDK |

Both call the same module functions and emit identical evidence/parity files
(`-mg` suffix on the SDK variant), so reports remain comparable.

## 3. Graph app registration (Phase 2)

- Microsoft Graph → Application permission **`Mail.ReadWrite`** → admin consent.
- Scope: `https://graph.microsoft.com/.default`.
- v1.0 endpoints only (`/users/{upn}/mailFolders/...`). **No beta by default**;
  the `/admin/exchange/mailboxes/...` mailboxFolder surface is a separate
  investigation and never a silent default.
- Same ApplicationAccessPolicy note applies.

## 4. Audit-first workflow (the gates)

| Gate | What must be true before proceeding |
|------|-------------------------------------|
| 1 | EWS OAuth works (audit script connects). |
| 2 | Read-only physical census completes; CSV/JSON evidence written. |
| 3 | The falsifier printed the ACTUAL physical count (16 / 261 / C). Evidence reviewed by operator. |
| 4 | Item-level physical-tag census understood (`-IncludeItemAudit`). |
| 5 | ONE controlled `PolicyTag=$null` pilot succeeded; before/after fixtures captured. |
| 6 | Bulk EWS `-Apply` (only after operator review of Gate 5). |
| 7 | Graph read parity report clean. |
| 8 | Graph write probe — only on a disposable folder, only after Gate 7, and only "proven" if EWS re-read matches the Gate-5 fixture. |

Commands (Parameter direkt oder via `-ConfigPath ./configs/<name>.json` — siehe
[Config-Examples.md](Config-Examples.md); CLI schlägt Config schlägt Default):

```powershell
# Gate 1-4 (read-only; -KnownEffectiveCount 261 from the external EXO census)
./Invoke-MrmRetentionAudit.ps1 -TenantId <tid> -ClientId <app> -CertificateThumbprint <tp> `
    -Mailbox user@contoso.com -TargetRetentionId d94993b5-e987-4275-8707-072057cfb2b8 `
    -KnownEffectiveCount 261 -IncludeItemAudit

# Gate 5 (pilot: ONE folder, fixtures)
./Invoke-MrmRetentionRepair.ps1 ... -Apply -PilotFolderPath '/Archive/Projects/ProjectB' -CaptureFixture

# external verification between gates (operator, EXO PowerShell):
Get-MailboxFolderStatistics <mbx> -IncludeAnalysis |
    Select FolderPath,DeletePolicy,RetentionFlags

# Gate 6 (bulk)
./Invoke-MrmRetentionRepair.ps1 ... -Apply

# Gate 7 (Graph read parity)
./Invoke-MrmGraphParity.ps1 ... -EwsCensusJson ./evidence/folder-census-<ts>.json

# Gate 8 (explicitly experimental, disposable folder only)
./Invoke-MrmGraphParity.ps1 ... -ExperimentalWriteProbe -ProbeGraphFolderId <id> -IUnderstandThisIsAnExperiment
```

## 4b. Troubleshooting: EWS assembly will not load

`Add-Type` fails with `FileLoadException` / HRESULT **0x80131515** and every
`Microsoft.Exchange.WebServices.Data.*` type is then "not found":

```powershell
Get-ChildItem .\lib\*.dll | Unblock-File
```

The DLL carries a `Zone.Identifier` alternate data stream (marked as downloaded
from the internet) and .NET refuses to load it. The tool now unblocks
proactively and verifies the type actually resolves before reporting success --
it will no longer continue with a null service.

## 5. Restore-before-MFA operational ordering

```
MFA disabled externally          (Set-Mailbox -ElcProcessingDisabled $true — operator, NOT this tool)
→ Recoverable Items restored     (operator, NOT this tool)
→ audit folder/item retention    (Phase 1A/1B — this tool, read-only)
→ EWS surgical untag             (Phase 1C — this tool, -Apply)
→ verify                          (re-audit + external Get-MailboxFolderStatistics -IncludeAnalysis)
→ Graph parity work              (Phase 2A, optional 2B experiment)
→ ONLY the human operator later decides when to re-enable ELC / run MFA
```

The tool never calls `Start-ManagedFolderAssistant`, never changes
`ElcProcessingDisabled`, never restores, moves, or deletes items — enforced by
an AST-based unit test over every shipped file.

**Item caveat (from Phase 1B evidence):** the 18,677 deleted items in
Recoverable Items carry `PolicyTag = d94993b5-...` **on the items**. Clearing
folders does not strip item-level stamps. If restored items still carry the tag
physically, whether MFA re-deletes them depends on their retention flags
(`UserOverride`/`ExplicitTag` semantics) — this is exactly why Gate 4 exists and
why item repair is a separate, evidence-gated decision, not an automatic path.

## 6. Rollback limitations

- Removing a PolicyTag is idempotent, but **restoring** it requires knowing the
  prior RetentionId + period + flags. That knowledge exists ONLY in the before
  snapshots. Therefore every write path (a) re-captures live state immediately
  before mutating and (b) appends full before/after JSON to
  `evidence/untag-changes-*.jsonl`. Keep that file.
- Tenant runs add a per-mailbox safety net under
  `evidence/tenant-repair/logging/<mbx>/backup-tagstate-*.json`
  (schema `mrm-tagstate-backup/1`): the complete pre-write tag state of every
  stamped folder, validated fail-closed before any write. This file is the
  restore source.
- To roll back manually, a folder can be re-stamped via EWS
  (`$folder.PolicyTag = [PolicyTag]::new($true,'<guid>')`) — deliberately NOT
  implemented in this tool to keep its mutation surface single-purpose.

## 7. Fixtures

`tests/fixtures/ews-policytag-null-before.json` / `...-after.json` are captured
by the Gate-5 pilot (`-CaptureFixture`), **redacted** (no mailbox identifiers,
no display names, no subjects), and become the contract Graph 2B must match.
The shipped placeholders document the expected schema; they are replaced by
live captures.

## 8. Known reference caveats

- `xedoc64/RemovePersonalRetentionTag` demonstrates the correct native
  operation (`PolicyTag = null; Update()`) but its `-retentionid` filter is
  unsafe: the non-matching branch still removes the tag. This tool inverts
  that: **non-match ⇒ no write**, enforced by `Test-MrmWriteAllowed` + tests.
- `gscales/ReportTagged.ps1` supplies the physical-vs-effective methodology
  (`Exists(PR_POLICY_TAG)`, 0x3019/0x301A/0x301D, 0x66B5). Its manual GUID hex
  shuffle is byte-identical to `System.Guid([byte[]])` — proven by unit test,
  so the tool uses the .NET type as the single canonical converter.
