# RC16 Quarantänegruppen-, Build- und Paketnachweis

Stand: 27. Juli 2026, Release Candidate `2.0.0-rc.16`

## Inhalt des Release Candidates

RC16 verbessert die Bedienbarkeit der Quarantäne, ohne die sicherheitsrelevante Einzelfreigabe
abzuschwächen:

- zusammengehörige Dateien werden anhand einer stabilen Vorgangskennung gruppiert;
- Codex-Runtime-Stagingpfade erscheinen als **Codex Runtime Installation**;
- jeder Gruppenkopf zeigt Quelle, enthaltene Dateizahl und Sammelstatus;
- Gruppen sind aufklappbar; die einzelnen Dateien bleiben mit Name, Quelle, Größe,
  Klassifizierung und Status sichtbar;
- Freigaben bleiben dateibezogen und benötigen weiterhin Zielpfad und Begründung;
- die Benachrichtigung spricht präzise von Dateien aus einem Download- oder
  Installationsvorgang.

Nicht erkannte Einzelquellen werden unter **Einzelne Downloads und Dateien** zusammengefasst. Die
Gruppierung ist eine Darstellungsschicht. Objekt-ID, Quarantänezustand, Brokerfreigabe,
Minifilterbestätigung und Auditierung bleiben unverändert.

## Automatisierter Nachweis

Der RC16-Regressionslauf bestand lokal:

| Prüfung | Ergebnis |
|---|---|
| Visual-Studio-x64-Release-Build | bestanden |
| Visual-Studio-x64-Debug-Build | bestanden |
| CTest Release | 18 von 18 |
| CTest Debug | 18 von 18 |
| WPF-Vertrag | 62 Controls, 6 Ansichten, Quarantänegruppierung bestanden |
| Codex-Runtime-Beispiel | 11 Dateien, eine Gruppe, korrekte Quelle und korrekter Status |
| Enterprise-Windows-Vertrag | bestanden |

Die WPF-Prüfung rendert denselben Elf-Dateien-Fall. Sie prüft:

- Gruppentitel `Codex Runtime Installation`;
- Quelle `codex-runtime-install-S0oO6J`;
- Dateizahl `11`;
- Status `Prüfung/Freigabe erforderlich`;
- sichtbaren Dateinamen `README.md`;
- den präzisierten Benachrichtigungstext.

## ABI- und Treiberstand

RC16 ändert keine Kernel- oder Transportstruktur:

- Kernel-Transport ABI `1.2`;
- ABI-Freeze Revision `3`;
- internes ABI `2.0`;
- Policyformat `1`.

Die drei lokal testsignierten Treiber werden unverändert aus dem qualifizierten Release-Staging
übernommen. Microsoft-Produktionstreibersignierung und HLK/WHCP bleiben externe Produktgates.

## Pakete und Installation

Der eingefrorene Stand erzeugt reproduzierbar:

- `AI_Shield_Private_Desktop.zip`;
- `AI_Shield_Private_Desktop_2.0.0-rc.16.zip`;
- `AI_Shield_Private_Desktop_2.0.0-rc.16_x64.msi`;
- `AI_Shield_Developer_ABI2_2.0.0-rc.16.zip`;
- `AI_Shield_Developer_Full_2.0.0-rc.16.zip`;
- `SHA256SUMS-2.0.0-rc.16.txt`.

Die äußeren SHA-256-Werte stehen in der gemeinsam veröffentlichten Summendatei. Desktop- und
Developer-Full-Paket enthalten zusätzlich ein internes dateibezogenes SHA-256-Manifest.

Die lokale Installationsfreigabe erfolgt erst, wenn:

1. die MSI-Authenticode-Signatur gültig ist;
2. Windows Installer das vorhandene Produkt erfolgreich aktualisiert;
3. Broker und Core automatisch laufen;
4. WFP, Minifilter und ProcessGuard `state=4` und `win32_exit=0` melden;
5. die installierte UI `2.0.0-rc.16` und den gruppierten Quarantänevertrag enthält.

## Fortbestehende externe Gates

RC16 ist ein Entwicklungs- und Pilot-Release. Microsoft-Signierung, HLK/WHCP,
Hardware-/Kompatibilitätsmatrix, Langzeit- und Neustartqualifikation sowie unabhängige
Sicherheitsprüfung bleiben erforderlich.
