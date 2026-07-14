# AI Shield Dokumentation

Stand: 14. Juli 2026, Release Candidate `2.0.0-rc.9`

Dieser Ordner ist der zentrale Einstieg in die Projekt-, Betriebs- und Entwicklungsdokumentation.
Der aktuelle Vertrag verwendet Kernel-Transport ABI `1.2` (Freeze-Revision `2`) und intern ABI
`2.0`. Die lokal gebauten Treiber sind Testsignaturen; eine öffentliche Auslieferung unter aktivem
Secure Boot setzt weiterhin Microsoft-signierte Treiber voraus.

## Editionen und Einstieg

| Zielgruppe | Einstieg | Zweck |
|---|---|---|
| Private Endanwender | [Private Desktop Handbuch](PRIVATE_DESKTOP_HANDBUCH_DE.md) | Installation, grafische Bedienung, Schutz, Audit und Quarantäne auf einem Einzelplatz-PC |
| Verwaltete Umgebung | [Enterprise-Betriebsprofil](ENTERPRISE_EDITION_HANDBUCH_DE.md) | WEF, SIEM, WDAC, Browserverwaltung, Policy- und Rolloutprozesse |
| Entwicklerteam | [Developer Full Handbuch](DEVELOPER_FULL_HANDBUCH_DE.md) | Vollständiger Build, Tests, Treiberpaket und Referenzinstallation |
| Sicherheitsanalyse | [Audit Viewer](AUDIT_VIEWER_DE.md) | AISHAD02 prüfen, anzeigen, filtern und als JSON dekodieren |
| Downloadkontrolle | [Downloadschutz und Freigabeschranke](DOWNLOADSCHUTZ_UND_FREIGABE_DE.md) | Policy v3, Dateigruppen, Quarantäne, Warnungen und Freigabe |
| Wiederherstellung | [Ransomware-Schutz und Recovery](RANSOMWARE_SCHUTZ_UND_RECOVERY_DE.md) | Versionsspeicher, Erkennung, externe Sicherung und bestätigte Rücksicherung |
| RC9-Systemnachweis | [RC9 Release- und Installationsnachweis](RC9_RELEASE_NACHWEIS_DE.md) | Policy v3, Download-Freigabeschranke, Tests und veröffentlichte Artefakte vom 14. Juli 2026 |
| Architekturentscheidung | [Editionen und Versionen](EDITIONEN_UND_VERSIONEN_DE.md) | Gemeinsamer Core, Unterschiede und Freigabestatus |

## Technische Referenz

- [Architekturübersicht](overview.md) und [Architektur-Whiteboard](ARCHITEKTUR_WHITEBOARD_DE.md)
- [ABI 2.0](ABI_2_0_DE.md) und [ABI Freeze/HLK](ABI_FREEZE_UND_HLK_DE.md)
- [Entwickler-Schnellstart](ENTWICKLER_SCHNELLSTART_DE.md)
- [Windows-Prototyphandbuch](PROTOTYP_HANDBUCH_DE.md)
- [Netzwerkschutz](NETZWERKSCHUTZ_DE.md), [Schutzabdeckung](SCHUTZABDECKUNG_2_0_DE.md) und
  [Kernel-/Hardware-Schutz](KERNEL_HARDWARE_SCHUTZ_DE.md)
- [Ransomware-Schutz und Wiederherstellung](RANSOMWARE_SCHUTZ_UND_RECOVERY_DE.md)
- [Downloadschutz und Freigabeschranke](DOWNLOADSCHUTZ_UND_FREIGABE_DE.md)
- [RC9 Release- und Installationsnachweis](RC9_RELEASE_NACHWEIS_DE.md)
- [Historischer RC8-Nachweis](RC8_RELEASE_NACHWEIS_DE.md)
- [Windows-Hardening](WINDOWS_HARDENING_DE.md) und
  [Enterprise-Sicherheitsintegrationen](ENTERPRISE_SECURITY_INTEGRATIONS_DE.md)

## Produktstatus und Nachweise

- [Aktueller Build- und Installationsstand](AKTUELLER_INSTALLATIONSSTAND_DE.md)
- [Produktqualifikation](PRODUKTQUALIFIKATION_DE.md)
- [Noch auszuführende Produktnachweise](FEHLENDE_FUNKTIONEN_DE.md)
- [Softwarebewertung](Softwarebewertung.md) und [Whitepaper](WHITEPAPER_DE.md)
- [Auftrag für ein unabhängiges Security Review](EXTERNER_SECURITY_REVIEW_AUFTRAG_DE.md)

`AI_Shield.md` und `AI_Shield_Developer_Full.md` sind historische, generierte Quelltext-Snapshots
früherer Entwicklerpakete. Sie sind keine aktuellen Betriebshandbücher. Maßgeblich sind die oben
verlinkten Dokumente und die Verträge im Quellbaum.

## Sicherheitsregel

AI Shield ergänzt Windows Defender, Firewall, Secure Boot, HVCI, BitLocker, Updates und Backups. Es
ersetzt diese Kontrollen nicht und garantiert keinen Schutz vor sämtlichen denkbaren Angriffen.
Testsigning darf nur in einer kontrollierten Entwicklungs- oder Pilotumgebung eingesetzt werden.
