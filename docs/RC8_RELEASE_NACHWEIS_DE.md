# AI Shield RC8 Release- und Installationsnachweis

Stand: 13. Juli 2026, Release Candidate `2.0.0-rc.8`

## Zweck

Dieses Dokument hält den zuletzt auf dem Referenzrechner tatsächlich ausgeführten Stand fest. Es
trennt reproduzierbare lokale Ergebnisse von weiterhin extern oder langfristig auszuführenden
Produktnachweisen.

## Ausgeführte Verifikation

- Release-Freeze `AIShieldPrivateReleaseContract/1`: bestanden.
- CTest Release x64: `12/12` Ziele bestanden.
- UI-Vertrag: `54` gebundene Controls und `6` Hauptansichten bestanden.
- Recovery-Integration: Snapshot, Erkennung, Plan, Restore und externes Backup bestanden.
- Reparse-Point-Negativtest: defekte Junction wurde nicht verfolgt; Test bestanden.
- MSI: lokal test-signiert und mit SignTool `/pa` verifiziert.
- MSI-Reparaturinstallation: Exitcode `0`.
- Treiberzustand: WFP, Minifilter und ProcessGuard jeweils `state=4`, `win32_exit=0`.
- Dienste: `AIShieldBroker` und `AIShieldCore` laufen mit Starttyp `Automatic`.

## Reale Recovery-Baseline

| Merkmal | Ergebnis |
|---|---|
| Snapshot-ID | `20260713T1707257435075Z` |
| Erfasste Dateien | `13.353` |
| Übersprungene Dateien | `0` |
| Schutzwurzeln | Desktop, Dokumente, Bilder, Musik und Videos des angemeldeten Benutzers |
| Reparse-Verhalten | Junctions und symbolische Links werden nicht betreten |
| Objektmodell | SHA-256-inhaltsadressierter Vault mit atomarem Snapshot-Manifest |

Die Erstbaseline benötigte mehrere Minuten. Das ist reale I/O-Arbeit für Hashing,
Entropiemessung und erstmalige Objektkopien. Die Quotenberechnung und Manifestlisten wurden auf
lineare Laufzeit umgestellt. Normale UI-Starts erzeugen keinen weiteren Snapshot, solange eine
gültige Baseline existiert.

## Installierte Hashes

| Datei | SHA-256 |
|---|---|
| `ui\start_private_ui.ps1` | `B30FD8519FD93EF92339A9C095E544EF3ACD9D6BD4D9B7EAAF2D2E0A14AD6757` |
| `platform\windows\ransomware\ransomware_recovery.ps1` | `9D775905F782ED020AD1F6CF2EBC64D04CEB477A39BF9A1BECB7A31785AC45D7` |

## Verbleibende Nachweise

Microsoft-Produktionssignierung, Secure-Boot-/HLK-/HVCI-/Driver-Verifier-Matrix,
Vollplatten- und Stromausfalltests, mehrtägige Dauerläufe, repräsentative Fehlalarmmessungen und
unabhängige Sicherheitsprüfungen bleiben offen. Die lokale Testsignatur ist kein Ersatz für diese
Freigaben.
