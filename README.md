# MRM-RetentionRepair

*(English version: [README_EN.md](README_EN.md))*

Sicheres, evidenzgetriebenes Audit + chirurgisches Entfernen **eines** fehlerhaften
klassischen Exchange-Online-MRM-Personal-Retention-Tags aus einer Mailbox.
Zwei strikte Phasen: EWS Managed API 2.2 (OAuth, **Verhaltensorakel**) →
Microsoft Graph (Read-Parität; Write nur als abgesichertes Experiment, per
Default **nicht bewiesen**).

    MRM-RetentionRepair/
      MRM-RetentionRepair.psm1        Kernmodul (30 exportierte Funktionen)
      Invoke-MrmRetentionAudit.ps1    Phase 1A/1B — Read-only-Zensus + Item-Audit
      Invoke-MrmRetentionRepair.ps1   Phase 1C   — Dry-Run als Default, -Apply gegated
      Invoke-MrmGraphParity.ps1       Phase 2A/2B — tokenbasiert ("oldschool"):
                                       rohes client_credentials + Invoke-RestMethod,
                                       NULL Modul-Abhängigkeiten (tokenhandler-Stil)
      Invoke-MrmTenantTagReport.ps1   Tenant-weiter READ-ONLY-Report physisch
                                       gestempelter Retention-Tags über viele
                                       Postfächer — modernisiertes ReportTagged.ps1
                                       (gscales), bewusst ohne Mg-Modul
      Invoke-MrmTenantTagRepair.ps1   Tenant-weites Nullen EINES physischen
                                       PolicyTags über viele Postfächer —
                                       DryRun (Default) -> -TestRun (gedeckelt)
                                       -> -Apply; pro Ordner die Evidenz-Zelle
                                       READ -> BACKUP -> SET -> READ -> COMPARE
      Invoke-MrmGraphParity.Mg.ps1    Phase 2A/2B — Microsoft.Graph-SDK-Variante:
                                       Connect-MgGraph / Invoke-MgGraphRequest
                                       (braucht nur Microsoft.Graph.Authentication)
      lib/                             EWS Managed API 2.2 (NuGet, net40; lädt unter pwsh7)
      tests/                           Pester-Suite (33 Tests) + Fixtures
      docs/RUNBOOK.md                  Operator-Runbook, Gates, EWS-Retirement-Hinweise

Kompatibilität
--------------
- Windows PowerShell 5.1 UND PowerShell 7+ (PSScriptAnalyzer
  PSUseCompatibleSyntax mit Targets 5.1/7.0: sauber; alle Dateien tragen eine
  UTF-8-BOM, damit 5.1 Nicht-ASCII nicht als ANSI fehlinterpretiert).
- Retry-After wird über BEIDE Header-APIs gelesen (WebHeaderCollection-Indexer
  für die HttpWebResponse von 5.1, GetValues für die HttpResponseMessage von 7)
  — dasselbe duale Muster wie PSScript/tokenhandler.
- Zwei Graph-Client-Varianten, gleiches Modul, gleiches Evidence-Format:
  * tokenbasiert (Default, keine Module)  -> Invoke-MrmGraphParity.ps1
  * Microsoft.Graph SDK                   -> Invoke-MrmGraphParity.Mg.ps1
- Die EWS-Phase ist immer Raw-OAuth (EWS Managed API 2.2 DLL, per
  Install-MrmEwsManagedApi automatisch von NuGet geladen oder aus lib/).
- Tests: Pester 5+/6 unter pwsh (Hinweis: ein Describe-Name darf kein "<->"
  enthalten — Escaped-Flow-Control-Bug in Pester 6.1.0).


Anleitung (Quickstart)
----------------------
1. **Config anlegen** (interaktiv; Secret wird verdeckt abgefragt und
   DPAPI-verschlüsselt gespeichert — Benutzer+Maschine-gebunden):

       ./Manage-MrmConfig.ps1 -Action Create -ConfigPath ./configs/TENANT-A.json
       ./Manage-MrmConfig.ps1 -Action Test   -ConfigPath ./configs/TENANT-A.json   # Pflichtfelder + EWS/Graph-Token
       ./Manage-MrmConfig.ps1 -Action Show   -ConfigPath ./configs/TENANT-A.json   # Secrets maskiert

   Beispiel-JSONs mit Dummy-Daten: [docs/Config-Examples.md](docs/Config-Examples.md).
   CLI-Parameter überschreiben Config-Werte, Config überschreibt Defaults.

2. **Gate 1–4 — Read-only-Audit** (Zensus + Falsifier + Item-Audit):

       ./Invoke-MrmRetentionAudit.ps1 -ConfigPath ./configs/TENANT-A.json -IncludeItemAudit

3. **Gate 5 — Pilot** (genau EIN Ordner, Fixtures für den Graph-Vertrag):

       ./Invoke-MrmRetentionRepair.ps1 -ConfigPath ./configs/TENANT-A.json `
           -Apply -PilotFolderPath '/Archive/Projects/ProjectB' -CaptureFixture

   Dazwischen extern verifizieren:
   `Get-MailboxFolderStatistics <mbx> -IncludeAnalysis | Select FolderPath,DeletePolicy,RetentionFlags`

4. **Gate 6 — Bulk** (Dry-Run ist Default; ohne `-Apply` passiert nichts):

       ./Invoke-MrmRetentionRepair.ps1 -ConfigPath ./configs/TENANT-A.json -Apply

5. **Gate 7 — Graph-Read-Parität** (tokenbasiert oder Mg-SDK, gleiches Evidence-Format):

       ./Invoke-MrmGraphParity.ps1    -ConfigPath ./configs/TENANT-A.json -EwsCensusJson ./evidence/folder-census-<ts>.json
       ./Invoke-MrmGraphParity.Mg.ps1 -ConfigPath ./configs/TENANT-A.json -EwsCensusJson ./evidence/folder-census-<ts>.json

6. **Gate 8 — Write-Experiment** (nur Wegwerf-Ordner, doppelt gegated):

       ./Invoke-MrmGraphParity.ps1 -ConfigPath ./configs/TENANT-A.json `
           -ExperimentalWriteProbe -ProbeGraphFolderId <id> -IUnderstandThisIsAnExperiment

Alle Gates, Reihenfolge (Restore VOR MFA!) und Rollback-Grenzen: [docs/RUNBOOK.md](docs/RUNBOOK.md).

**Tenant-Report** (read-only, unabhängig von den Gates — z. B. "wo klebt dieses
Tag noch überall?"):

       # Postfachliste aus CSV, nur das Incident-Tag:
       ./Invoke-MrmTenantTagReport.ps1 -ConfigPath ./configs/TENANT-A.json `
           -MailboxCsv ./mailboxes.csv -FilterRetentionId d94993b5-e987-4275-8707-072057cfb2b8

       # oder Discovery über rohes Graph-REST (App-Permission User.Read.All, kein Mg-Modul):
       ./Invoke-MrmTenantTagReport.ps1 -ConfigPath ./configs/TENANT-A.json -DiscoverViaGraph -Resume

   Liefert pro Postfach JSON, konsolidiertes CSV und ein Tenant-Rollup
   (welche RetentionIds, wie viele Ordner/Postfächer, Perioden, Flags,
   Beispielpfade). -Resume überspringt bereits gescannte Postfächer.
   Wie im Original zählt nur der PHYSISCHE Stempel (Exists 0x3019/0x3018) —
   rein vererbte Tags erscheinen bewusst nicht.

**Tenant-Repair** (Nullen des Tags über viele Postfächer — bewusst langsame
Lernkurve, Erfahrungen sammeln vor der Breite):

       # Stufe 1 — DryRun (Default): Kandidaten je Postfach, null Writes.
       #   Modus 1: ein User, mehrere kommagetrennt, oder als Array — alles gleichwertig:
       ./Invoke-MrmTenantTagRepair.ps1 -ConfigPath ./configs/TENANT-A.json `
           -Mailbox 'a@contoso.com,b@contoso.com' -TargetRetentionId d94993b5-e987-4275-8707-072057cfb2b8

       # Stufe 2 — Testlauf: schreibt, aber gedeckelt auf 1 Postfach x 1 Ordner (Default),
       #   mit voller Evidenz-Zelle pro Ordner: READ -> BACKUP (JSONL) -> SET -> READ -> COMPARE (Verified)
       ./Invoke-MrmTenantTagRepair.ps1 -ConfigPath ./configs/TENANT-A.json `
           -Mailbox 'a@contoso.com,b@contoso.com' -TargetRetentionId d94993b5-... -TestRun

       # Stufe 3 — Vollauf über ALLE User-Postfächer (Modus 2, Graph-Discovery ohne Mg):
       ./Invoke-MrmTenantTagRepair.ps1 -ConfigPath ./configs/TENANT-A.json `
           -AllMailboxes -TargetRetentionId d94993b5-... -Apply

   **Safety-Net pro Postfach:** unter `evidence/tenant-repair/logging/<mbx>/`
   liegt vor jedem Write ein vollständiges Tag-State-Backup
   (`backup-tagstate-*.json`, Schema `mrm-tagstate-backup/1`) mit allem, was
   ein manuelles Re-Stamping braucht (FolderId, RetentionId, Periode, Flags) —
   **fail-closed**: das Backup wird nach dem Schreiben rückgelesen und
   validiert (Schema, Mailbox, Ordnerzahl); ohne verifiziertes Backup schreibt
   das Tool in diesem Postfach nicht. Dazu Pre-/Post-Zensus und die
   JSONL-Before/After-Paare jeder Mutation im selben Ordner.

   -TestRun und -Apply schließen sich aus; jede Mutation prüft live vor dem
   Write (Exact-Match-Invariante), sichert den Vorzustand als JSONL, liest nach
   und vergleicht (Verified). Unerwarteter Nachzustand stoppt das Postfach.
   Pro Postfach liegen Pre-/Post-Zensus + Backups unter evidence/tenant-repair/<mbx>/.

Leitplanken
-----------
- Schreibzugriff nur, wenn die aktuell gelesene physische RetentionId EXAKT dem
  Ziel entspricht; Nicht-Treffer ⇒ kein Write (der invertierte xedoc64-Bug).
- Geschützte Tags (z. B. "Never Delete") sind niemals entfernbar — erzwungen im
  Code und per Test.
- Kein Start-ManagedFolderAssistant, kein Set-Mailbox, kein Restore/Delete/Move
  — ein AST-basierter Test verbietet diese Cmdlets in jeder ausgelieferten Datei.

Tests ausführen:  pwsh -c "Invoke-Pester -Path ./tests"
Einstieg:         docs/RUNBOOK.md
Referenzen:       PSScript/tokenhandler (Throttling-/Token-Muster),
                  PSScript/Resend-GraphReplay (client_credentials + 429-Handling)
