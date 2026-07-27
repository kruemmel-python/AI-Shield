# Qualifikationsstatus AI Shield Private Desktop 2.0.0-rc.16

Stand: 27. Juli 2026

## Bestätigte lokale Gates

- Kernel-Transport ABI 1.2, Freeze-Revision 3 und internes ABI 2.0 entsprechen dem Releasevertrag.
- Release- und Debug-Build bestehen jeweils alle 18 CTest-Ziele einschließlich Datei-Scanner-, Tray-,
  Einzelinstanz-, Close-to-Tray- und Enterprise-Vertrag.
- Der Enterprise-Agent-Vertrag prüft TPM-bindbare Geräteidentität, Clone Detection,
  Zertifikatsrotation, Anti-Rollback, Rollout-Ringe, feste Remote-Response-Aktionen ohne
  Remote-Shell, Nonce-Replay, RBAC, Dual Control und hashverkettete Fleet-Batches.
- Windows-Enrollment und detached CMS verlangen HTTPS, Client-Auth, SHA-256-Zertifikatpin,
  vollständige Zertifikatkette und Online-Widerrufsprüfung. Enrollment-Zustand ist per
  DPAPI LocalMachine und restriktiver ACL geschützt.
- Alle User-Mode-Binärdateien werden mit Control Flow Guard, CET, ASLR und DEP/NX gebaut.
- Der WPF-Vertrag enthält 62 gebundene Controls in sechs Ansichten. Die Quarantänegruppierung
  wird mit elf Dateien eines Codex-Runtime-Installationsvorgangs geprüft; Titel, Quelle,
  Dateizahl, Sammelstatus, Aufklappbarkeit und Einzelfreigabe bleiben gebunden.
- Der Tray-Vertrag und der reale Laufzeittest bestätigen Einzelinstanz, Fünf-Komponenten-Status,
  maschinenweiten Anmeldeautostart und eine vom Schutzkern unabhängige Beendigung.
- Content-Policy v4 migriert v1/v2/v3 und aktiviert elf Dateigruppen, Fail-closed und die
  Freigabeschranke standardmäßig.
- ZIP-/ZIP64-Tiefenanalyse deckt Stored, Fixed-/Dynamic-DEFLATE, Data Descriptor, CRC,
  Verschachtelung und Ressourcenbudgets ab.
- Das latenzbegrenzte Minifilter-Pending-Protokoll bindet Request-, Volume- und File-ID an den
  registrierten Broker. Die Übergabe ist auf 250 ms begrenzt; ein separater Worker setzt das
  endgültige Urteil. Timeout, Überlast und Identitätsfehler bleiben fail-closed.
- Der RC13-Freigabetest bestätigt den direkten Brokerpfad, die identitätsgebundene Minifilter-
  Freigabe, `state=committed`, lesbaren Dateiinhalt und die anschließende Bereinigung.
- Der reale Regressionstest bestätigte 15,1 ms Download-Cleanup, 25,5 ms Dienstabfrage und einen
  nach 665,8 ms erkannten UI-Prozess bei laufendem Minifilter. 200 normale Temp-Dateien benötigten
  insgesamt 933,9 ms; die Download-Testdatei wurde anschließend aus dem Downloadordner entfernt.
- Der reale Downloadtest quarantänisierte eine aktive PDF und verlangte auch für eine saubere
  Bilddatei eine begründete Freigabe.
- Der RC14-Schaltertest bestätigt: `.crdownload` bleibt bis zum finalen Rename unangetastet,
  deaktivierter Archivschutz lässt ZIP-Dateien ohne Inhaltsprüfung zu und ein aktivierter
  Archivschutz klassifiziert dieselbe Datei nach dem Rename neu.
- Der ProcessGuard-Laufzeittest blockierte direkte Temp-Ausführung und verschleierte
  PowerShell-Kommandos. Normale URL-Befehle blieben erlaubt. Bei ausgeschaltetem Download-
  Ausführungsschutz liefen `.ps1` und `.bat`; bei eingeschaltetem Schutz wurden beide blockiert.
- WFP, Minifilter und ProcessGuard wurden mit WDK `/W4 /WX` neu gebaut, testsigniert, installiert
  und mit `state=4` geladen.
- Broker und Core laufen als automatische LocalSystem-Dienste.
- Der MSI-Deinstallationspfad prüft nach dem Rückbau ausdrücklich, dass Broker, Core und alle drei
  Treiberregistrierungen verschwunden sind; ein unvollständiger Rückbau beendet das MSI mit Fehler.
- Das signierte RC16-MSI wurde mit Windows Installer/WiX erzeugt und seine lokale
  Authenticode-Testsignatur erfolgreich verifiziert.
- Desktop-, ABI2- und Developer-Full-ZIP besitzen sichere Pfade; Desktop- und Full-Manifeste wurden
  vollständig gegen SHA-256 geprüft.
- Der eingefrorene RC16-Quellvertrag ist gültig.

## Signierte Treiberhashes

| Datei | SHA-256 der vollständigen signierten Datei |
|---|---|
| `AIShieldWfp.sys` | `60DF032CA04F9BF0F90D696EB4478E0B8850D714CCA1D24004B688E61389B351` |
| `AIShieldMiniFilter.sys` | `63CFBF7482596E73FF7AA2109BDC35D9000034EF33A1B15BB6607220779D27EB` |
| `AIShieldProcessGuard.sys` | `FBAEF84400510EE2DE54E5E5EDB0B103AFBBD6DD1D594F49AD17AD3D12021811` |

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
