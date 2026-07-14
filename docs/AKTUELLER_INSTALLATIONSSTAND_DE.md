# AI Shield: Aktueller Build- und Installationsstand

Stand: 13. Juli 2026

## Build

Der aktuelle Quellstand wurde mit Visual Studio 2022, Windows SDK/WDK 10.0.26100.0 und CMake als
x64-Release gebaut. Alle zwölf CTest-Ziele bestanden. Anschließend wurden WFP-, Minifilter- und
ProcessGuard-Treiber mit `/W4 /WX` neu gebaut, lokal test-signiert und installiert.

Reproduzierbarer administrativer Ablauf:

```powershell
powershell -ExecutionPolicy Bypass `
  -File platform\windows\installer\deploy_current_prototype.ps1
```

Das Skript stoppt alte Komponenten, baut User Mode und WDK, führt CTest aus, aktualisiert das
Treiberpaket, signiert und installiert die Treiber, installiert Broker und Core-Orchestrator und
aktiviert abschließend eine neue signierte Audit-Policy. Das Transkript liegt unter
`runtime\deploy-current-prototype.log`.

## Signierte Treiber

Alle drei Paketdateien besitzen eine gültige Signatur des lokalen Testzertifikats
`125D756E7666534CDF4558A2B9E96E96907B3FFC`.

| Datei | SHA-256 der vollständigen signierten Datei |
|---|---|
| `AIShieldMiniFilter.sys` | `A2D57DF519C6BB46AC4CC130CB0255D97115D52CC85BF4DC1D6EFA06C46D01E7` |
| `AIShieldProcessGuard.sys` | `0E8C643B1CAF96CA3ECD5D344A2057961E28E264AEBE0F8B5E994125A3A93B58` |
| `AIShieldWfp.sys` | `96BB3CBD64E1ACEFF9A402D7C5D06FAC74465C1B1F8F03FE4F6E58141BC27A9E` |

Lokales Testsigning ersetzt keine Microsoft-Produktionssignatur.

## Installierter Status

```text
AIShieldWfp: state=4 win32_exit=0
AIShieldMiniFilter: state=4 win32_exit=0
AIShieldProcessGuard: state=4 win32_exit=0
```

```text
AIShieldBroker       Running Automatic
AIShieldCore         Running Automatic
AIShieldMiniFilter   Running System
AIShieldProcessGuard Running System
AIShieldWfp          Running System
```

Ein früherer Installationslauf meldete folgenden geschützten Runtime-State; Policy- und
Generationsnummern können sich bei jeder Aktivierung erhöhen:

```text
runtime generation=1 policy=11 model=1
```

Der Core-Orchestrator meldete:

```json
{"schema":2,"safe_mode":false,"unhealthy_components":0,"policy_available":true,
 "audit_writable":true,"gateway_alive":false}
```

`gateway_alive=false` ist ohne HTTP-Backend korrekt: Treiber, Broker und Core laufen mit der
signierten systemweiten Enforcement-Policy, während noch kein HTTP-Gateway fuer ein konkretes Backend gestartet wurde.
Der optionale HTTP-Gateway wird ueber `platform\windows\start_ai_shield.ps1` mit einem konkreten
Backend gestartet; `AI_Shield_Start_Demo.cmd` startet den isolierten Demo-Modus.

Der sichere Standardstart ist `AI_Shield_Start.cmd` beziehungsweise
`AI_Shield_Protect_System.cmd`. Er aktiviert IPv4-/IPv6-Flowkontrolle
fuer TCP und UDP sowie den Wurm-Egress-Schutz. Die strengere, kompatibilitaetskritische Variante ist
`AI_Shield_Protect_System_Strict.cmd`. Details stehen in `NETZWERKSCHUTZ_DE.md`.

## Auditformat

Das Projekt erzeugt und akzeptiert ausschließlich `AISHAD02`. Frühere Auditformatversionen sind
nicht im Produktreader vorhanden und werden fail-closed abgelehnt.

Der Microsoft Platform Crypto Provider wurde auf diesem Testsystem mit
`provider=1 hardware=1 key=1` verifiziert. Der optionale maschinenweite TPM-Anker ist provisioniert.

Broker und Core laufen jetzt aus `C:\Program Files\AIShield\bin`. Der Installer verifiziert die
kopierten SHA-256-Werte und setzt restriktive Verzeichnis- und Service-ACLs. Die reversible
Defender-Auditbaseline ist aktiv: zwölf ASR-Regeln, Network Protection und Controlled Folder Access
arbeiten im Auditmodus; PUA-Schutz blieb im bereits strengeren Enforcement-Modus.

Der erweiterte Posture-Bericht besteht aktuell mit `16/28`; vier kritische Befunde bleiben sichtbar:
Secure Boot ist fuer die Testsignierung deaktiviert, TESTSIGNING ist aktiv, die Windows-Firewall ist
deaktiviert und UAC fordert bei diesem Administratorkonto keine Zustimmung an. Die Defender-
Auditbaseline wurde real angewendet, zurueckgerollt und erneut angewendet. Ein simulierter
unterbrochener Erstupdate-Vorgang wurde real recovered; beide Dienste kehrten laufend auf ihre
geschuetzten Program-Files-Binaerpfade zurueck.

Die AI-Shield-WDAC-Policy ist im Windows-Code-Integrity-Inventar vorhanden, liegt im Auditmodus und
ist nicht erzwungen. Der signierte Browser-Host und die lokal ladbare Edge-/Chrome-Erweiterung sind
in Private Desktop integriert; ohne Store- oder HTTPS-Updatequelle bleibt je Browser die einmalige
Ordnerbestätigung erforderlich. WEF und PowerShell-Forwarding sind ohne externe HTTPS-Ziele und
Zertifikatpins korrekt unkonfiguriert. Die Firewalltransaktion ist implementiert und muss mit den
konkreten VPN- und Entwicklungsallowlists des Zielsystems abgestimmt werden.

Die Private-Desktop-UI besitzt jetzt einen DPAPI-geschützten Dateityp-Schutz für Dokumente,
Archive, Bilder, Audio, Video und Webdateien. Neue Mark-of-the-Web-Downloads werden abhängig von
dieser Policy durch einen isolierten, zeitbegrenzten Defender-/AMSI- und Struktur-Scanner geprüft.
Der integrierte Audit Viewer validiert und dekodiert lokale oder exportierte AISHAD02-Dateien.

Credential Guard ohne UEFI-Lock ist fuer den naechsten kontrollierten Neustart vorbereitet. Defender
Cloud Protection ist mit Advanced MAPS, Safe Samples und Block-at-First-Seen aktiv. PowerShell
Script-Block- und Microsoft-Modul-Logging sind lokal aktiv; die externe datensparsame Weiterleitung
wartet weiterhin auf SOC-Endpoint und Zertifikatpin.

## RC8-Recovery-Nachweis auf dem Referenzrechner

Die installierte Private-Desktop-MSI wurde am 13. Juli 2026 als Reparaturinstallation mit
`REINSTALL=ALL` und `REINSTALLMODE=vomus` aktualisiert. Windows Installer meldete Exitcode `0`.
Der installierte UI-Hash und der Hash des Recovery-Moduls wurden danach gegen den eingefrorenen
Quellstand geprüft.

Die erste reale Recovery-Baseline verarbeitete `13.353` Dateien aus Desktop, Dokumenten, Bildern,
Musik und Videos. Es wurden `0` Dateien übersprungen. Der Snapshot besitzt die ID
`20260713T1707257435075Z`. Windows-Kompatibilitäts-Junctions und andere Reparse Points werden nicht
verfolgt; ein Integrationstest mit absichtlich nicht auflösbarem Junction-Ziel ist Bestandteil des
zwölften CTest-Gates.

Die Vault-Quotenberechnung erfolgt einmal pro Snapshot. Datensatz- und Fehlerlisten verwenden
lineare Collections. Damit wurde der zuvor auf realen Profilen quadratisch wachsende Aufwand
beseitigt. Hashen, Entropiemessung und erstmaliges Kopieren der tatsächlichen Dateiinhalte bleiben
bewusst notwendige I/O-Arbeit.
