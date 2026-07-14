# AI Shield: Produktqualifikation und Microsoft-Treibersignierung

Stand: 14. Juli 2026

## Ausgefuehrte Hardening- und Recovery-Nachweise

- Defender-Auditbaseline mit zwoelf ASR-Regeln, Network Protection und Controlled Folder Access
  erfolgreich aktiviert, vollstaendig zurueckgerollt und erneut aktiviert.
- Vorhandenes PUA-Enforcement wurde waehrend der Auditstaffelung nicht abgeschwaecht.
- Unterbrochenes erstes A/B-Update mit Transaktionsschema 2 simuliert.
- Broker und Core wurden durch den Recovery-Pfad neu gestartet und kehrten auf die vorherigen,
  validierten Program-Files-Pfade zurueck.
- Service-DACL und geschuetzter Installationspfad sind aktiv; normale Benutzer koennen Status lesen,
  Dienste aber nicht steuern oder rekonfigurieren.
- 16 von 16 CTest-Zielen bestanden, einschließlich Datei-Scanner-, Recovery-, Tray-, UI- und
  Minifilter-Latenzvertragstests.
- Der Recovery-Test deckt Snapshot, Vorfallerkennung, Wiederherstellungsplan, bestätigten Restore,
  externe Backupprüfung und eine absichtlich defekte Junction ab.
- Eine reale Erstbaseline auf dem Referenzrechner erfasste 13.353 Dateien ohne übersprungene
  Einträge. Die installierte MSI-Reparatur, UI und Recovery-Dateien wurden per SHA-256 verifiziert.

## Zweck

Dieses Dokument beschreibt die ausführbaren Release-Gates für Last, Missbrauch, Installation,
Recovery und Neustart sowie die lokale Vorbereitung einer externen Microsoft-Treibersignierung.
Alle Qualifikationsskripte benötigen eine administrative PowerShell. Ein bestandener lokaler Lauf
ersetzt weder HLK noch Microsoft-Signierung oder eine unabhängige Sicherheitsprüfung.

## Qualifikationsharness

Das Skript `tests\windows_product_qualification.ps1` schreibt pro Lauf ein maschinenlesbares JSON
unter `runtime\qualification\<UTC-Lauf-ID>\result.json`. Jeder Check enthält Name, Ergebnis und
Evidenz. Ein fehlgeschlagenes Gate beendet den Prozess mit Exitcode 2.

Schneller Last- und Missbrauchstest:

```powershell
powershell -ExecutionPolicy Bypass `
  -File tests\windows_product_qualification.ps1 `
  -Suite quick -DurationMinutes 1 -Concurrency 4
```

Der Test sendet parallel normale und unterschiedlich kodierte Path-Traversal-Anfragen über den
transparent geschützten Backend-Port. Er verlangt erlaubte und blockierte Antworten, null
Transportfehler, keinen zusätzlichen Queue-Verlust, drei gesunde Treiber, einen laufenden Broker
und gültige Auditsegmente.

Dauertest, beispielsweise 24 Stunden:

```powershell
powershell -ExecutionPolicy Bypass `
  -File tests\windows_product_qualification.ps1 `
  -Suite soak -DurationMinutes 1440 -Concurrency 8
```

Recovery-Drill:

```powershell
powershell -ExecutionPolicy Bypass `
  -File tests\windows_product_qualification.ps1 `
  -Suite recovery -DurationMinutes 10 -Concurrency 4
```

Zusätzlich zur Laststrecke stoppt und startet dieser Lauf den Broker, prüft die RSA-Signatur der
aktiven Policy und verlangt `recovery_required=False`.

Kontrollierter Remove/Reinstall-Zyklus:

```powershell
powershell -ExecutionPolicy Bypass `
  -File tests\windows_product_qualification.ps1 `
  -Suite install -ConfirmInstallCycle
```

Der explizite Schalter verhindert unbeabsichtigte Deinstallation. Das Gate entfernt alle drei
Treiberdienste, bestätigt den Zwischenzustand, baut und signiert neu, installiert die Treiber,
stellt den Broker wieder her und reaktiviert die zuletzt gültige signierte Policy.

## Neustartqualifikation

Die Neustartprüfung wird vorbereitet, startet den Rechner aber nicht selbst:

```powershell
powershell -ExecutionPolicy Bypass `
  -File tests\windows_product_qualification.ps1 `
  -Suite quick -DurationMinutes 1 -Concurrency 2 -ArmReboot
Restart-Computer
```

`-ArmReboot` schreibt einen geschützten Fortsetzungszustand und registriert die einmalige
SYSTEM-Aufgabe `AIShieldQualificationResume`. Nach dem nächsten Start werden `SYSTEM_START` aller
Treiber, der verzögerte Brokerstart und Policy-Recovery geprüft. Zustand und Aufgabe werden danach
entfernt. Ein Neustart darf nur auf einem vorgesehenen Testsystem erfolgen.

## Verifizierte lokale Ergebnisse

Der einminütige Lauf mit vier Workern ergab:

```text
http-load allowed=3141 blocked=3141 failed=0
telemetry-loss dropped=0
audit-integrity count=20 bad=0
```

Ein weiterer Recovery-Lauf mit zwei Workern ergab 2043 erlaubte und 2043 blockierte Antworten,
keine Transportfehler, keinen Telemetrieverlust, 20 gültige Auditsegmente und eine weiterhin gültige
Policy Version 3. Der echte Remove/Reinstall-Zyklus bestätigte dreimal `not installed`, installierte
alle Treiber neu und stellte signiertes Enforcement wieder her.

Nach Implementierung der automatischen Provenance und Policy Version 5 bestand der erweiterte
Recovery-Lauf zusätzlich folgende Gates:

```text
http-load allowed=1977 blocked=1977 failed=0
telemetry-loss before=864 after=864 delta=0
audit-integrity count=20 bad=0
hvci-runtime services_running=2
process-guard-rules passed
automatic-provenance-quarantine moved=True restored=True
policy signature=valid security_version=5 mode=enforce
```

Der historische Minifilter-Zähler 864 entstand während eines vorherigen Brokerstopps. Das Gate
bewertet deshalb korrekt den Zuwachs im Testfenster; dieser war null.

## HVCI und Driver Verifier

Das Laborwerkzeug `platform\windows\verification\driver_security_lab.ps1` erfasst VBS-, HVCI- und
Verifier-Zustand. Auf dem aktuellen Testsystem meldet `SecurityServicesRunning=2` laufende Memory
Integrity, während Secure Boot wegen der lokalen Testsignierung deaktiviert bleibt.

```powershell
powershell -ExecutionPolicy Bypass `
  -File platform\windows\verification\driver_security_lab.ps1 `
  -Action preflight
```

Driver Verifier und HVCI-Systemänderungen verlangen `-ConfirmSystemChange`, lösen aber keinen
automatischen Neustart aus. Der vollständige Ablauf und der Notfallreset stehen in
`docs\DRIVER_SECURITY_LAB_DE.md`.

## Microsoft-Submission vorbereiten

```powershell
powershell -ExecutionPolicy Bypass `
  -File platform\windows\installer\prepare_microsoft_submission.ps1
```

Das Skript erzeugt unter `submission\microsoft`:

- getrennte Pakete für WFP, Minifilter und ProcessGuard
- je eine INF-, SYS-, PDB- und CAT-Datei
- `AIShieldDrivers-x64.cab`
- `SHA256SUMS.json`
- eine Submission-Checkliste

`Inf2Cat` läuft für `10_X64,Server10_X64`. Alle drei Pakete müssen ohne Fehler und Warnungen
signierbar sein. Optional kann ein vorhandenes EV-Zertifikat verwendet werden:

```powershell
powershell -ExecutionPolicy Bypass `
  -File platform\windows\installer\prepare_microsoft_submission.ps1 `
  -EvCertificateThumbprint <EV-FINGERPRINT> `
  -TimestampUrl https://<ZEITSTEMPEL-DIENST>
```

Der private EV-Schlüssel darf nicht in das Repository oder in Buildausgaben exportiert werden.

## Externe Gates

Für moderne 64-Bit-Windows-Systeme muss ein neuer Kernel-Treiber durch Microsoft über das Hardware
Developer Center signiert werden. Für eine öffentliche Produktionsfreigabe ist der HLK-/WHCP-Weg
das Ziel; Attestation Signing ist nach aktueller Microsoft-Dokumentation auf Testszenarien
beschränkt und nicht für die Veröffentlichung an ein Retail-Publikum über Windows Update gedacht.

Erforderlich bleiben:

1. Organisationsregistrierung im Windows Hardware Developer Program.
2. Aktuelles EV-Code-Signing-Zertifikat gemäß Partner-Center-Anforderungen.
3. Passende Windows-HLK-Version und alle anwendbaren Playlists pro Zielbetriebssystem.
4. EV-signiertes HLK- oder zulässiges Attestation-Submission-Paket.
5. Upload und Verarbeitung im Partner Center.
6. Download des von Microsoft signierten Rückpakets.
7. Lokale Prüfung des Rückpakets:

```powershell
powershell -ExecutionPolicy Bypass `
  -File platform\windows\installer\verify_microsoft_signed_package.ps1 `
  -PackageDirectory D:\Pfad\Zum\Microsoft-Rueckpaket
```

Das Rückpaket-Gate erwartet genau drei SYS- und drei CAT-Dateien, prüft jede Datei mit
`SignTool verify /kp /all /v` und schreibt ein neues SHA-256-Manifest. Danach müssen Installations-,
Neustart-, Secure-Boot-, HVCI-, Driver-Verifier-, Last- und Recovery-Gates mit genau diesen
Binärdateien erneut ausgeführt werden.

Offizielle Referenzen:

- [Microsoft: Attestation sign Windows drivers](https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/code-signing-attestation)
- [Microsoft: Windows Hardware Lab Kit](https://learn.microsoft.com/en-us/windows-hardware/test/hlk/)
- [Microsoft: Driver signing](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/driver-signing)
- [Microsoft: Creating a catalog with Inf2Cat](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/creating-a-catalog-file-for-a-pnp-driver-package)
