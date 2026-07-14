# AI Shield RC12 Release- und Installationsnachweis

Stand: 15. Juli 2026, Release Candidate `2.0.0-rc.12`

## Funktionsumfang

RC12 ergänzt den RC11-Dateischutz um:

- rekursive ZIP-/ZIP64-Tiefenanalyse für Stored und Fixed-/Dynamic-DEFLATE;
- Central-Directory-, Local-Header-, Data-Descriptor-, CRC- und Pfadkonsistenz;
- gemeinsame Rekursions-, Eintrags-, Größen- und Kompressionsbudgets;
- authentisierten Filter-Manager-Port zwischen Minifilter und registriertem Broker;
- Request-/Volume-/File-ID-gebundene Pending-Übergabe mit 250-ms-Kerneldeadline und getrenntem
  Analyse-Worker;
- fail-closed Verhalten bei Timeout, Portausfall, Identitätswechsel und ungültigen Antworten;
- IRQL-sichere Post-Cleanup-Ausführung über `FltDoCompletionProcessingWhenSafe`.

Die ursprüngliche RC12-Vorabimplementierung wartete bis zu 30 Sekunden im Cleanup-Pfad und bezog
das allgemeine Benutzer-Temp-Verzeichnis ein. Der qualifizierte RC12-Stand entfernt diese
Desktop-Blockade: Die Empfangsbestätigung ist auf 250 ms begrenzt, die Inhaltsanalyse läuft
asynchron, und nur das betroffene Dateiobjekt bleibt bis zum endgültigen Urteil gesperrt.

## Lokale Buildnachweise

| Prüfung | Ergebnis |
|---|---|
| Release CTest | 16/16 bestanden |
| Debug CTest | 16/16 bestanden |
| ABI-Freeze | gültig, Revision 2 |
| ABI-Fingerprint | `8152bb2807a796ae7f5bd234edfb11624ffb07ac263b2eb69a83b02c97d06a65` |
| WFP-Treiber | `/W4 /WX`, 0 Warnungen, 0 Fehler |
| Minifilter | `/W4 /WX`, 0 Warnungen, 0 Fehler |
| ProcessGuard | `/W4 /WX`, 0 Warnungen, 0 Fehler |
| Aktive Temp-I/O-Probe | 200 Dateien in 933,9 ms |
| Aktiver Download-Cleanup | 15,1 ms, anschließend quarantänisiert |
| UI-Startprobe | Prozess nach 665,8 ms erkannt |
| MSI-Gleichversions-Neuinstallation | Deinstallation 0, Installation 0 |

## Artefakte

Der GitHub-Release `v2.0.0-rc.12` enthält:

- `AI_Shield_Private_Desktop.zip`;
- `AI_Shield_Private_Desktop_2.0.0-rc.12_x64.msi`;
- `AI_Shield_Developer_ABI2.zip`;
- `AI_Shield_Developer_Full.zip`;
- `SHA256SUMS.txt`.

Die endgültigen äußeren SHA-256-Werte stehen in `SHA256SUMS.txt`. Desktop- und Developer-Full-
Pakete enthalten zusätzlich vollständige interne Dateimanifeste.

## Vertrauensgrenze

Die Treiber sind lokal testsigniert. Der Nachweis ist ein Entwicklungs- und Pilotnachweis, keine
Microsoft-Produktionsfreigabe. Secure Boot muss für diesen lokalen Prototyp deaktiviert und
`TESTSIGNING` aktiviert sein. Microsoft-Signierung, HLK/WHCP, Driver-Verifier-/HVCI-Neustartläufe,
Langzeit- und unabhängige Sicherheitstests bleiben externe Produktnachweise.
