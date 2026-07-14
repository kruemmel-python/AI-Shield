# Qualifikationsstatus AI Shield Private Desktop 2.0.0-rc.10

Stand: 14. Juli 2026

## Bestätigte lokale Gates

- Kernel-Transport ABI 1.2, Freeze-Revision 2 und internes ABI 2.0 entsprechen dem Releasevertrag.
- Release- und Debug-Build bestehen jeweils alle 14 CTest-Ziele einschließlich Tray-,
  Einzelinstanz- und Close-to-Tray-Vertrag.
- Der WPF-Vertrag enthält 61 gebundene Controls in sechs Ansichten.
- Der Tray-Vertrag und der reale Laufzeittest bestätigen Einzelinstanz, Fünf-Komponenten-Status,
  maschinenweiten Anmeldeautostart und eine vom Schutzkern unabhängige Beendigung.
- Content-Policy v3 migriert v1/v2 und aktiviert zehn Dateigruppen, Fail-closed und die
  Freigabeschranke standardmäßig.
- Der reale Downloadtest quarantänisierte eine aktive PDF und verlangte auch für eine saubere
  Bilddatei eine begründete Freigabe.
- Der ProcessGuard-Laufzeittest blockierte direkte Temp-Ausführung, riskante PowerShell-Kommandos
  sowie heruntergeladene `.ps1`- und `.bat`-Dateien.
- WFP, Minifilter und ProcessGuard wurden mit WDK `/W4 /WX` neu gebaut, testsigniert, installiert
  und mit `state=4` geladen.
- Broker und Core laufen als automatische LocalSystem-Dienste.
- Das signierte RC10-MSI wurde erfolgreich mit Windows Installer/WiX erzeugt und seine lokale
  Authenticode-Testsignatur verifiziert.
- Desktop-, ABI2- und Developer-Full-ZIP besitzen sichere Pfade; Desktop- und Full-Manifeste wurden
  vollständig gegen SHA-256 geprüft.
- Der eingefrorene RC10-Quellvertrag ist gültig.

## Signierte Treiberhashes

| Datei | SHA-256 der vollständigen signierten Datei |
|---|---|
| `AIShieldWfp.sys` | `96BB3CBD64E1ACEFF9A402D7C5D06FAC74465C1B1F8F03FE4F6E58141BC27A9E` |
| `AIShieldMiniFilter.sys` | `6BC8B6BC6936E430F27CC155007B4E285D82AAE411D0CE0C1478B863C706F2E4` |
| `AIShieldProcessGuard.sys` | `6C964917579995C7BADBF51FF49457941B49FD02497FC0EAE27A7009ADF79023` |

Die Signatur stammt vom lokalen Zertifikat `AI Shield Prototype Test Signing`. Sie ersetzt keine
Microsoft-Produktionstreibersignatur.

## Release-Artefakte

Desktop-ZIP, signiertes MSI, ABI2-Quellpaket und Developer-Full-Paket werden reproduzierbar aus
diesem Freeze erzeugt. Die endgültigen äußeren Paket-Hashes stehen bewusst nur in der neben den
Artefakten veröffentlichten Datei `SHA256SUMS.txt`; dadurch enthält kein Paket seinen eigenen,
rekursiv instabilen Hash. Interne Dateien bleiben über die Paketmanifeste hashgedeckt.

## Noch nicht bestandene externe oder rebootpflichtige Gates

1. Microsoft Partner Center, EV-Identität, HLK/WHCP und Microsoft-Produktionstreibersignierung.
2. Driver Verifier und HVCI über kontrollierte Neustarts auf jeder unterstützten Windows-Version.
3. Vollplatten-, Stromausfall-, Upgrade-, Rollback-, 24-Stunden- und 30-Tage-Dauertests.
4. Repräsentative Fehlalarm- und Kompatibilitätsmessungen mit Browsern, VPNs, Spielen, Installern,
   Entwicklertools und realen Nutzerdaten.
5. Unabhängiges Threat Modeling, Kernel-Code-Review, Penetrationstest und Datenschutzprüfung.
6. Öffentliche Browser-Store-/HTTPS-Verteilung statt lokaler Erweiterungsbestätigung.

Keiner dieser Punkte darf ohne Ergebnisartefakt als bestanden markiert werden.
