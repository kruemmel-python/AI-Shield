# AI Shield RC13 Release- und Installationsnachweis

Stand: 15. Juli 2026, Release Candidate `2.0.0-rc.13`

## Funktionsumfang

RC13 ergänzt RC12 um einen vollständigen, transaktionalen Freigabepfad aus der Quarantäne:

- direkter erhöhter Brokeraufruf aus der Desktop-UI ohne blockierten PowerShell-Unterprozess;
- Validierung von Quarantäne-ID, Begründung, Linkanzahl, Volume- und File-ID;
- write-through Move und erneute Identitätsprüfung am Ziel;
- dauerhaftes Restore-Journal mit `committed` und `rolled_back`;
- administratives Minifilter-Urteil für genau die freigegebene Datei-ID;
- automatischer Rücktransport in die Quarantäne bei fehlgeschlagener Kernelbestätigung;
- absichtliche Ablehnung von Cross-Volume-Zielen, solange keine identische Datei-ID erhalten bleibt.

Die Kernel-Transportstrukturen und deren Größen bleiben ABI `1.2`. Der additive administrative
IOCTL erhöht die Freeze-Revision auf `3`; das interne Ereignis- und Auditformat bleibt ABI `2.0`
beziehungsweise `AISHAD02`.

## Lokale Nachweise

| Prüfung | Ergebnis |
|---|---|
| Release CTest | 16/16 bestanden |
| Debug CTest | 16/16 bestanden |
| WFP-Treiber | `/W4 /WX`, 0 Warnungen, 0 Fehler |
| Minifilter | `/W4 /WX`, 0 Warnungen, 0 Fehler |
| ProcessGuard | `/W4 /WX`, 0 Warnungen, 0 Fehler |
| Quarantänisierung einer harmlosen Probe | erfolgreich |
| Freigabe nach Downloads | erfolgreich |
| Restore-Journal | `state=committed` |
| Freigegebener Inhalt | lesbar und anschließend bereinigt |

## Artefakte

Der GitHub-Release `v2.0.0-rc.13` enthält:

- `AI_Shield_Private_Desktop.zip`;
- `AI_Shield_Private_Desktop_2.0.0-rc.13_x64.msi`;
- `AI_Shield_Developer_ABI2.zip`;
- `AI_Shield_Developer_Full.zip`;
- `SHA256SUMS.txt`.

Die äußeren SHA-256-Werte stehen in `SHA256SUMS.txt`. Consumer- und Developer-Full-Pakete enthalten
zusätzlich interne Dateimanifeste.

## Vertrauensgrenze

Die Treiber und das MSI sind lokal testsigniert. RC13 ist ein Entwicklungs- und Pilotnachweis,
keine Microsoft-Produktionsfreigabe. Für die Testsignatur muss Secure Boot deaktiviert und Windows
`TESTSIGNING` aktiviert sein. Microsoft-Signierung, HLK/WHCP, Driver-Verifier-/HVCI-Neustartläufe,
Langzeit-, Kompatibilitäts- und unabhängige Sicherheitstests bleiben externe Produktnachweise.
