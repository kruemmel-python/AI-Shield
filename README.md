# AI Shield

AI Shield ist eine modulare Windows-Sicherheitsplattform in C++23. Sie erfasst Netzwerk-, Datei-
und Prozessereignisse an systemnahen Kontrollpunkten, übersetzt sie in einen authentisierten
ABI-2.0-Vertrag und bewertet sie anhand lokaler Richtlinien. Der aktuelle Stand verbindet drei
Windows-Kerneltreiber, LocalSystem-Dienste, isolierte Parser, Downloadquarantäne, Audit-Ketten,
Recovery-Funktionen und eine grafische Private-Desktop-Oberfläche.

> **Projektstatus:** `2.0.0-rc.10` ist ein funktionsfähiger Entwicklungs- und Pilotprototyp. Die
> Private-Desktop-Ausgabe kann auf einem einzelnen Windows-PC installiert und getestet werden. Die
> enthaltenen Treiber sind lokal testsigniert. Eine öffentliche Produktionsverteilung unter
> aktiviertem Secure Boot erfordert weiterhin Microsoft-Treibersignierung, HLK/WHCP-Qualifikation,
> Kompatibilitätsmessungen und eine unabhängige Sicherheitsprüfung.

## Kernfunktionen

- Dual-Stack-WFP-Sensorik für IPv4/IPv6, TCP/UDP und konfigurierbare Enforcement-Regeln.
- Minifilter-Telemetrie mit Datei-/Volume-Identität und TOCTOU-resistenter Quarantäne.
- ProcessGuard-Regeln für Downloads, Skriptinterpreter, LOLBins, Office-Kindprozesse,
  Credential Access und Persistenzmuster.
- Signierte, monotone Policies sowie authentisierte ABI-2.0-Korrelation über Broker, Audit,
  Kausalgraph, Incident-Paket und Replay.
- Isolierte PDF-, ZIP-, PE-, Defender- und AMSI-Prüfung mit Zeit- und Ressourcenlimits.
- Download-Freigabeschranke für Programme, Skripte, Dokumente, Archive, Bilder, Audio, Video,
  Webdateien und Windows-Systemaktionen.
- Manipulationssichtbare `AISHAD02`-Audit-Kette mit integriertem Viewer und JSON-Export.
- Ransomware-Erkennung, versionierter Recovery-Vault, externe Sicherung und bestätigte
  hashverifizierte Wiederherstellung.
- Private-Desktop-UI für Schutzfunktionen, Quarantäne, Audits, Recovery und Windows-Härtung.
- Automatischer Tray-Agent mit Komponentenstatus, Einzelinstanz und Close-to-Tray ohne erneute UAC-Abfrage.

## Architektur

```text
Netzwerk ──► WFP-Treiber ─────────┐
Dateien  ──► Minifilter ──────────┼─► AIShieldBroker ─► ABI 2.0 / Audit
Prozesse ──► ProcessGuard ────────┘         │
                                             ├─► Parser und Detektoren
Browser  ──► Native-Messaging-Sensor ────────┤
                                             ├─► Policy und Quarantäne
                                             └─► AIShieldCore / Desktop-UI
```

Die WFP-Komponenten erfassen systemweite IPv4-/IPv6-Ereignisse. Transparente Umleitung und
Blockierung werden nur für die explizit aktivierten Regeln und Zielports durchgesetzt. HTTPS- und
QUIC-Nutzdaten werden ohne TLS-Interception nicht entschlüsselt; AI Shield installiert keine
lokale MITM-Zertifizierungsstelle.

## Reifestatus

| Bereich | Status |
|---|---|
| Shared Core und internes ABI 2.0 | Implementiert und automatisiert getestet |
| Broker, Core-Dienst, Audit und Replay | Implementiert und lokal betreibbar |
| Private-Desktop-UI, Tray und Quarantäne | Implementiert; RC10-Pilotstand |
| WFP-, Minifilter- und ProcessGuard-Treiber | WDK-Prototyp, lokal testsignierbar |
| Edge-/Chrome-Sensor | Lokal ladbar; Store-/HTTPS-Verteilung ausstehend |
| Microsoft-Produktionstreibersignierung | Ausstehender externer Meilenstein |
| HLK, Langzeit-, Last- und Kompatibilitätsnachweise | Ausstehend beziehungsweise teilweise lokal vorbereitet |
| Unabhängiger Kernel-Review und Penetrationstest | Ausstehend |

## Desktop-Schnellstart

Für einen bereits vorbereiteten Entwicklungsrechner:

```powershell
Set-Location <Pfad-zum-AI-Shield-Repository>
.\AI_Shield_Start.cmd
```

Die Oberfläche startet über:

```powershell
.\editions\private_desktop\AI_Shield_UI.cmd
```

In **Schutzfunktionen > Dateityp-Schutz** sind alle zehn Dateigruppen und die Option
**Freigabe vor dem Öffnen erzwingen** standardmäßig aktiv. Neue Downloads mit Mark-of-the-Web
werden geprüft, aus `Downloads` in die Quarantäne verschoben und in der UI gemeldet. Erst eine
begründete Freigabe stellt die Datei wieder bereit.

Die aktuelle Desktop-Ausgabe steht zusätzlich als MSI- und ZIP-Artefakt im
[GitHub-Release](https://github.com/kruemmel-python/AI-Shield/releases/latest) bereit.

## Voraussetzungen

- Windows 11 x64; Windows 10 x64 nur nach separater Kompatibilitätsprüfung.
- Visual Studio 2022 mit MSVC-C++-Desktopentwicklung.
- CMake und Windows SDK; WDK für den Treiberbuild.
- Windows PowerShell 5.1 für Installationsskripte, PowerShell 7 optional für Entwicklung.
- Administratorrechte für Dienste, Treiber, Firewall- und Security-Einstellungen.
- Genügend freier Speicher für Build, Audit, Quarantäne und Recovery-Vault.

### Wichtiger Secure-Boot-Hinweis

Die veröffentlichten RC10-Treiber sind **nicht Microsoft-produktionssigniert**. Für lokale
Testsignierung muss Secure Boot in der UEFI-Firmware deaktiviert und Windows `TESTSIGNING`
aktiviert werden. Das schwächt die Windows-Startvertrauenskette und ist nur für kontrollierte
Entwicklungs- oder Pilotgeräte vorgesehen. Vor UEFI-Änderungen muss ein BitLocker-
Wiederherstellungsschlüssel extern gesichert und geprüft werden.

Fehler `577` beim Treiberstart bedeutet, dass Windows die Signatur unter der aktuellen
Bootrichtlinie abgelehnt hat.

## Quellcode bauen

```powershell
$CMAKE_EXE = "C:\Program Files\CMake\bin\cmake.exe"
$CTEST_EXE = "C:\Program Files\CMake\bin\ctest.exe"

& $CMAKE_EXE -S . -B build_vs -G "Visual Studio 17 2022" -A x64
& $CMAKE_EXE --build build_vs --config Release --parallel
& $CTEST_EXE --test-dir build_vs -C Release --output-on-failure
```

Ein Debug-Lauf ist zusätzlich erforderlich, weil Release-Builds klassische `assert`-Ausdrücke
entfernen können:

```powershell
& $CMAKE_EXE -S . -B build_vs_debug -G "Visual Studio 17 2022" -A x64
& $CMAKE_EXE --build build_vs_debug --config Debug --parallel
& $CTEST_EXE --test-dir build_vs_debug -C Debug --output-on-failure
```

## Windows-Treiber

Treiber bauen:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\platform\windows\build_drivers.ps1 -Configuration Release
```

Lokales Testpaket signieren und aktualisieren, aus einer administrativen PowerShell:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\platform\windows\installer\update_and_install_drivers.ps1 `
  -Configuration Release

.\build_vs\Release\ai_shield_driverctl.exe status
```

Die WDK-Pipeline erzeugt `AIShieldWfp.sys`, `AIShieldMiniFilter.sys` und
`AIShieldProcessGuard.sys` sowie die zugehörigen INF-Dateien. Öffentliche Installation unter
Secure Boot setzt von Microsoft signierte Kataloge und den externen Submission-Prozess voraus.

## Diagnose und Tests

```powershell
.\build_vs\Release\ai_shield_broker.exe self-test
.\build_vs\Release\ai_shield_diag.exe audit-verify <audit.bin>
.\build_vs\Release\ai_shield_replay.exe <scenario.bin>
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\editions\private_desktop\ui\verify_ui_contract.ps1
```

Der reale Downloadtest benötigt Administratorrechte und einen laufenden Broker:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\tests\windows_download_content_protection.ps1
```

## Dokumentation

### Erste Schritte

- [Dokumentationsübersicht](docs/README.md)
- [Entwickler-Schnellstart](docs/ENTWICKLER_SCHNELLSTART_DE.md)
- [Private-Desktop-Handbuch](docs/PRIVATE_DESKTOP_HANDBUCH_DE.md)
- [Developer-Full-Handbuch](docs/DEVELOPER_FULL_HANDBUCH_DE.md)

### Architektur und Sicherheitsmodell

- [Architekturübersicht](docs/overview.md)
- [Architektur-Whiteboard](docs/ARCHITEKTUR_WHITEBOARD_DE.md)
- [Whitepaper](docs/WHITEPAPER_DE.md)
- [Schutzabdeckung](docs/SCHUTZABDECKUNG_2_0_DE.md)
- [Netzwerkschutz](docs/NETZWERKSCHUTZ_DE.md)
- [ABI 2.0](docs/ABI_2_0_DE.md)

### Installation und Betrieb

- [Aktueller Installationsstand](docs/AKTUELLER_INSTALLATIONSSTAND_DE.md)
- [Windows-Prototyphandbuch](docs/PROTOTYP_HANDBUCH_DE.md)
- [Windows-Hardening](docs/WINDOWS_HARDENING_DE.md)
- [Ransomware-Schutz und Recovery](docs/RANSOMWARE_SCHUTZ_UND_RECOVERY_DE.md)
- [Enterprise-Betriebsprofil](docs/ENTERPRISE_EDITION_HANDBUCH_DE.md)

### Qualifikation und externe Prüfungen

- [RC10-Release-Nachweis](docs/RC10_RELEASE_NACHWEIS_DE.md)
- [Historischer RC9-Nachweis](docs/RC9_RELEASE_NACHWEIS_DE.md)
- [Produktqualifikation](docs/PRODUKTQUALIFIKATION_DE.md)
- [Noch auszuführende Produktnachweise](docs/FEHLENDE_FUNKTIONEN_DE.md)
- [Auftrag für unabhängiges Security Review](docs/EXTERNER_SECURITY_REVIEW_AUFTRAG_DE.md)
- [Softwarebewertung](docs/Softwarebewertung.md)

## Schutzgrenzen

AI Shield ergänzt Microsoft Defender, Windows-Firewall, Secure Boot, HVCI, BitLocker, Updates und
externe Backups. Es ersetzt diese Kontrollen nicht. Parser und Verhaltensregeln garantieren keinen
Schutz vor allen Zero-Days. Ein bereits privilegierter Angreifer, kompromittierte Firmware oder
Hardware und manipulierte Windows-Vertrauensanker liegen teilweise außerhalb der lokalen
Vertrauensgrenze. Audit-Verkettung macht Manipulationen sichtbar, ist ohne externes unveränderliches
Ziel aber nicht gegen jeden vollständig privilegierten Angreifer unveränderbar.

## Pakete

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tools\package_private_desktop.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tools\package_developer_release.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tools\package_developer_full.ps1
```

Jedes Paket enthält ein SHA-256-Manifest. Release-Hashes werden zusätzlich als GitHub-Assets
veröffentlicht.

## Lizenz

Copyright © 2026 Ralf Krümmel.

AI Shield wird unter der [Apache License 2.0](LICENSE) bereitgestellt. Hinweise zu Drittkomponenten
und Namensnennung stehen in [NOTICE](NOTICE).
