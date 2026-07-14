# Qualifikationsstatus AI Shield Private Desktop 2.0.0-rc.12

Stand: 15. Juli 2026

## Bestätigte lokale Gates

- Kernel-Transport ABI 1.2, Freeze-Revision 2 und internes ABI 2.0 entsprechen dem Releasevertrag.
- Release- und Debug-Build bestehen jeweils alle 16 CTest-Ziele einschließlich Datei-Scanner-, Tray-,
  Einzelinstanz- und Close-to-Tray-Vertrag.
- Der WPF-Vertrag enthält 61 gebundene Controls in sechs Ansichten.
- Der Tray-Vertrag und der reale Laufzeittest bestätigen Einzelinstanz, Fünf-Komponenten-Status,
  maschinenweiten Anmeldeautostart und eine vom Schutzkern unabhängige Beendigung.
- Content-Policy v4 migriert v1/v2/v3 und aktiviert elf Dateigruppen, Fail-closed und die
  Freigabeschranke standardmäßig.
- ZIP-/ZIP64-Tiefenanalyse deckt Stored, Fixed-/Dynamic-DEFLATE, Data Descriptor, CRC,
  Verschachtelung und Ressourcenbudgets ab.
- Das latenzbegrenzte Minifilter-Pending-Protokoll bindet Request-, Volume- und File-ID an den
  registrierten Broker. Die Übergabe ist auf 250 ms begrenzt; ein separater Worker setzt das
  endgültige Urteil. Timeout, Überlast und Identitätsfehler bleiben fail-closed.
- Der reale Regressionstest bestätigte 15,1 ms Download-Cleanup, 25,5 ms Dienstabfrage und einen
  nach 665,8 ms erkannten UI-Prozess bei laufendem Minifilter. 200 normale Temp-Dateien benötigten
  insgesamt 933,9 ms; die Download-Testdatei wurde anschließend aus dem Downloadordner entfernt.
- Der reale Downloadtest quarantänisierte eine aktive PDF und verlangte auch für eine saubere
  Bilddatei eine begründete Freigabe.
- Der ProcessGuard-Laufzeittest blockierte direkte Temp-Ausführung, riskante PowerShell-Kommandos
  sowie heruntergeladene `.ps1`- und `.bat`-Dateien.
- WFP, Minifilter und ProcessGuard wurden mit WDK `/W4 /WX` neu gebaut, testsigniert, installiert
  und mit `state=4` geladen.
- Broker und Core laufen als automatische LocalSystem-Dienste.
- Das signierte RC12-MSI wurde erfolgreich mit Windows Installer/WiX erzeugt und seine lokale
  Authenticode-Testsignatur verifiziert.
- Desktop-, ABI2- und Developer-Full-ZIP besitzen sichere Pfade; Desktop- und Full-Manifeste wurden
  vollständig gegen SHA-256 geprüft.
- Der eingefrorene RC12-Quellvertrag ist gültig.

## Signierte Treiberhashes

| Datei | SHA-256 der vollständigen signierten Datei |
|---|---|
| `AIShieldWfp.sys` | `60DF032CA04F9BF0F90D696EB4478E0B8850D714CCA1D24004B688E61389B351` |
| `AIShieldMiniFilter.sys` | `1465EC64DA3C386EC437F916632EBD5B66E8136258B045F659A62445A8B45D97` |
| `AIShieldProcessGuard.sys` | `A9D99C95EE77775DD7947CC73E53BF28D6768AD65195EEF65D06CEB7AB07C6F7` |

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
