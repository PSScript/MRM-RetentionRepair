# Beispiel-Konfigurationen / Example configuration files

**Zum Editieren:** die Vorlage `configs/TENANT-EXAMPLE.template.json` im Repo
kopieren (`configs/<NAME>.json`), Werte eintragen, dann
`./Manage-MrmConfig.ps1 -Action Encrypt -ConfigPath ./configs/<NAME>.json` —
das fragt das Client Secret verdeckt ab und ergänzt `ClientSecretEncrypted`.
Eigene `configs/*.json` sind gitignored, nur `*.template.json` ist versioniert.

Eine JSON-Datei pro Tenant/Run (Muster: `PSScript/Resend-GraphReplay`).
Secrets liegen **nie im Klartext** auf der Platte: `*Encrypted`-Felder sind
`ConvertFrom-SecureString`-Blobs — unter Windows DPAPI, d. h. **gebunden an
den erzeugenden Benutzer auf der erzeugenden Maschine**. Erzeugen/rotieren mit
`Manage-MrmConfig.ps1 -Action Create|Encrypt`, niemals von Hand kopieren.

## 1. TENANT-A.json — Zertifikat aus dem Store (empfohlen)

```json
{
    "TenantId": "12345678-1234-1234-1234-123456789012",
    "ClientId": "87654321-4321-4321-4321-210987654321",
    "CertificateThumbprint": "A1B2C3D4E5F60718293A4B5C6D7E8F9012345678",
    "CertificateStore": "Cert:\\CurrentUser\\My",
    "Mailbox": "user@contoso.com",
    "TargetRetentionId": "d94993b5-e987-4275-8707-072057cfb2b8",
    "KnownEffectiveCount": 261,
    "OutputDirectory": "C:\\MrmRepair\\evidence",
    "Description": "Tenant A — incident retention repair",
    "CreatedDate": "2026-08-25 09:00:00",
    "CreatedBy": "ops-admin"
}
```

## 2. TENANT-B.json — PFX-Datei (Passwort DPAPI-verschlüsselt)

```json
{
    "TenantId": "98765432-5678-5678-5678-567890123456",
    "ClientId": "11111111-2222-3333-4444-555555555555",
    "CertificatePath": "C:\\MrmRepair\\certs\\mrm-app.pfx",
    "CertificatePasswordEncrypted": "01000000d08c9ddf0115d1118c7a00c04fc297eb...",
    "Mailbox": "user@contoso.com",
    "TargetRetentionId": "d94993b5-e987-4275-8707-072057cfb2b8",
    "OutputDirectory": "C:\\MrmRepair\\evidence",
    "Description": "Tenant B — PFX-based",
    "CreatedDate": "2026-08-25 09:05:00",
    "CreatedBy": "ops-admin"
}
```

## 3. TEST-ENV.json — Client Secret (nur wenn Zertifikat nicht möglich)

```json
{
    "TenantId": "test-tenant-id-here",
    "ClientId": "test-client-id-here",
    "ClientSecretEncrypted": "01000000d08c9ddf0115d1118c7a00c04fc297eb...",
    "Mailbox": "test-mailbox@testdomain.com",
    "TargetRetentionId": "d94993b5-e987-4275-8707-072057cfb2b8",
    "EwsCensusJson": "C:\\MrmRepair\\evidence\\folder-census-20260825-090000.json",
    "MaxItemsPerFolder": 500,
    "OutputDirectory": "C:\\Temp\\mrm-evidence",
    "Description": "Test environment — secret auth (discouraged), small item cap",
    "CreatedDate": "2026-08-25 09:10:00",
    "CreatedBy": "developer"
}
```

## Feldreferenz

| Feld | Pflicht | Verwendet von | Bedeutung |
|---|---|---|---|
| `TenantId`, `ClientId` | ja | alle | Entra-App (app-only) |
| `Mailbox` | ja | alle | Ziel-Postfach (UPN) |
| `TargetRetentionId` | ja | alle | GUID des zu entfernenden Tags — geschützte GUIDs werden schon beim `Create`/`Test` abgelehnt |
| `CertificateThumbprint` (+`CertificateStore`) | eins von drei | alle | Zertifikat aus dem Store (bevorzugt) |
| `CertificatePath` (+`CertificatePasswordEncrypted`) | eins von drei | Audit/Repair | PFX-Datei |
| `ClientSecretEncrypted` | eins von drei | alle | DPAPI-Blob; Klartext-`ClientSecret` wird akzeptiert, aber laut angemeckert |
| `KnownEffectiveCount` | nein | Audit | Ordnerzahl aus externem `Get-MailboxFolderStatistics` (Falsifier-Kontext) |
| `EwsCensusJson` | für Parity | GraphParity(.Mg) | Pfad zum Phase-1A-Zensus |
| `MaxItemsPerFolder` | nein | Audit | Item-Audit-Deckel (Default 2000) |
| `PilotFolderPath` | nein | Repair | Gate-5-Pilot auf genau einen Ordner beschränken |
| `OutputDirectory` / `EvidenceDirectory` | nein | alle / Mg | Evidence-Ablage |
| `MailboxCsv` | nein | TenantTagReport | CSV mit Spalte Mailbox/UserPrincipalName/PrimarySmtpAddress/Mail |
| `ThrottleDelayMs` | nein | TenantTagReport/-Repair | Pause zwischen Postfächern (Report 250 / Repair 500) |

Priorität überall: **CLI-Parameter > Config-Wert > Skript-Default.**

### Zusätzliche App-Permission für den Tenant-Report

`-DiscoverViaGraph` nutzt rohes Graph-REST (`GET /v1.0/users`) und braucht die
Graph-**Application**-Permission `User.Read.All` (admin-consented) zusätzlich zu
`full_access_as_app` (EWS). Ohne Discovery (CSV/-Mailbox) reicht EWS allein.

## Secret-Handling — Regeln

1. `Manage-MrmConfig.ps1 -Action Create` fragt Secrets mit `Read-Host
   -AsSecureString` ab — nichts landet in History oder Konsole.
2. Auf der Platte nur `*Encrypted` (DPAPI: Benutzer+Maschine). Eine Config ist
   damit **nicht** auf andere Maschinen/Benutzer kopierbar — das ist Absicht;
   auf der Zielmaschine `-Action Encrypt` neu ausführen.
3. `-Action Show` maskiert Secrets, `-Action List` zeigt nur den Auth-Typ und
   brandmarkt Klartext-Configs (`Secret (PLAINTEXT!)`).
4. `-Action Test` validiert Pflichtfelder + Target-GUID und holt je einen
   app-only Token für EWS- und Graph-Scope — ohne Postfachzugriff.
5. Tokens werden nirgends geloggt (`Protect-MrmLogText` scrubbt Bearer/JWT/
   `client_secret` zusätzlich aus jeder Logzeile).
6. Nicht-Windows-Hinweis: dort ist `ConvertFrom-SecureString` ohne `-Key` nur
   Obfuskation, keine Kryptographie — Configs als Windows-Artefakte behandeln.
