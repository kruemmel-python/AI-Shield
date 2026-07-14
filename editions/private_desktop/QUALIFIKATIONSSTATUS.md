# Qualifikationsstatus AI Shield Private Desktop 2.0.0-rc.11

Stand: 14. Juli 2026

## Bestätigte lokale Gates

- Kernel-Transport ABI 1.2, Freeze-Revision 2 und internes ABI 2.0 entsprechen dem Releasevertrag.
- Release- und Debug-Build bestehen jeweils alle 15 CTest-Ziele einschließlich Datei-Scanner-, Tray-,
  Einzelinstanz- und Close-to-Tray-Vertrag.
- Der WPF-Vertrag enthält 61 gebundene Controls in sechs Ansichten.
- Der Tray-Vertrag und der reale Laufzeittest bestätigen Einzelinstanz, Fünf-Komponenten-Status,
  maschinenweiten Anmeldeautostart und eine vom Schutzkern unabhängige Beendigung.
- Content-Policy v4 migriert v1/v2/v3 und aktiviert elf Dateigruppen, Fail-closed und die
  Freigabeschranke standardmäßig.
- Der reale Downloadtest quarantänisierte eine aktive PDF und verlangte auch für eine saubere
  Bilddatei eine begründete Freigabe.
- Der ProcessGuard-Laufzeittest blockierte direkte Temp-Ausführung, riskante PowerShell-Kommandos
  sowie heruntergeladene `.ps1`- und `.bat`-Dateien.
- WFP, Minifilter und ProcessGuard wurden mit WDK `/W4 /WX` neu gebaut, testsigniert, installiert
  und mit `state=4` geladen.
- Broker und Core laufen als automatische LocalSystem-Dienste.
- Das signierte RC11-MSI wurde erfolgreich mit Windows Installer/WiX erzeugt und seine lokale
  Authenticode-Testsignatur verifiziert.
- Desktop-, ABI2- und Developer-Full-ZIP besitzen sichere Pfade; Desktop- und Full-Manifeste wurden
  vollständig gegen SHA-256 geprüft.
- Der eingefrorene RC11-Quellvertrag ist gültig.

## Signierte Treiberhashes

| Datei | SHA-256 der vollständigen signierten Datei |
|---|---|
| `AIShieldWfp.sys` | `424A0EE534231FC583EDC53CE693D7C8B7FAF90438FE0F09B7A631D281AD7F5E` |
| `AIShieldMiniFilter.sys` | `2FA9CACE0241FC12C4FBABBD4848A1A8885687EB6B811324CF3718B85D33077D` |
| `AIShieldProcessGuard.sys` | `29E2C8E017410BB54B47C19119997EA446BC29AF9FC31C8AE5C06A5D9716B3C8` |

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
