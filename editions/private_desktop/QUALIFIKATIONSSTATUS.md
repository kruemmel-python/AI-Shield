# Qualifikationsstatus AI Shield Private Desktop 2.0.0-rc.8

Stand: 13. Juli 2026

## Bestätigte lokale Gates

- Kernel-ABI 1.2, Freeze-Revision 2 und internes ABI 2.0 entsprechen dem Releasevertrag.
- Zwei vollständige, getrennte Release-Builds bestanden jeweils alle 11 CTest-Ziele.
- Ein vollständiger Debug-Build bestand alle 11 CTest-Ziele.
- Fünf auslieferungsrelevante User-Mode-Programme waren zwischen beiden Release-Builds hashgleich.
- Alle drei Treiber wurden zweimal mit WDK `Rebuild` erzeugt und waren jeweils hashgleich.
- Inf2Cat erzeugte für WFP, Minifilter und ProcessGuard Kataloge ohne Fehler und Warnungen.
- Das Microsoft-Staging enthält INF, SYS, CAT, PDB, ABI- und SHA-256-Manifeste sowie CAB.
- Zwei Consumer-Paketläufe aus identischen signierten Eingaben sind bytegenau reproduzierbar.
- Der WPF-Vertrag des RC3-Interfaces enthält 34 gebundene Controls in fünf Ansichten. Der
  Browsersensor besitzt eine stabile Chromium-ID, einen gültig signierten Native-Messaging-Host
  und getrennte Edge-/Chrome-Registrierung; alle Consumer-Manifestdateien sind hashgedeckt.
  Die manuelle lokale Erweiterungsaktivierung ersetzt keine spätere Store-/HTTPS-Verteilung.
- RC4 ergänzt eine transaktionale Kernel-/Hardware-Baseline für VBS/HVCI, verwundbare
  Treiberblockliste, TPM-Anker sowie bedingte Secure-Launch-/DMA-Konfiguration. Posture weist
  Secure Boot, Testsigning, DMA, SMM-Messung, Kernel-Stackschutz und BitLocker separat aus.
- Der lokale Consumer-Korpus bestand sichere Prozessstarts und harmlose Downloadtypen.
- Ein fünfsekündiger Dual-Stack-Lauf übertrug 2.166.210.560 Byte in 528.860 Transfers über
  dauerhafte IPv4-/IPv6-Flows ohne Transportfehler.
- Broker und Core blieben im Messfenster unter 10 MiB Working Set und weit unter 1 Prozent
  durchschnittlicher Gesamt-CPU.
- Auf dem Testsystem wurden installierte Anwendungen in allen fünf Inventarkategorien Browser,
  VPN, Spiele, Installer und Skript-/Entwicklungswerkzeuge gefunden.

Maschinenlesbare Nachweise:

- `runtime/private-release/RC_REPORT.json`
- `runtime/private-release/consumer-qualification.json`
- `runtime/private-release/microsoft-submission/SHA256SUMS.json`
- `runtime/verification/HLK_READINESS.json`

Frische, reproduzierte Treiberhashes:

| Datei | SHA-256 |
|---|---|
| `AIShieldWfp.sys` | `3F0CE985AF35B1CDB59AF5D7DC9066D11F6F92E05FCF656EADE0973C8EC99370` |
| `AIShieldMiniFilter.sys` | `0B1D9540D8A9336F5F8AD78CFD6D2C8EDA91FF6D7FB1E6661F9E991EE2AA4620` |
| `AIShieldProcessGuard.sys` | `7D6E3E6A2F0BB43CAA3C37C6E4499BCED1F4204623198912064C31658894CF0B` |
| `AIShieldDrivers-x64.cab` | `FD25FEF7B622C6CF73CA535DE4F3AA8F0A8AC5308E3005946681DCA988F9A12F` |

## Noch nicht bestandene Gates

Das installierbare RC-ZIP wurde absichtlich nicht freigegeben. Die frisch gebauten Treiber sind
noch nicht testsigniert und noch nicht anstelle der laufenden älteren Prototyptreiber installiert.
Der Packager verweigert unsignierte Consumer-Treiber.

Der erhöhte Abschlusslauf lautet:

```powershell
Set-Location D:\AI_Shield
powershell -ExecutionPolicy Bypass -File tools\complete_private_rc_admin.ps1 `
  -QualificationSeconds 60 -ConfirmInstallCycle
```

Dieser Lauf signiert exakt das geprüfte Staging, erstellt das reproduzierbare Consumer-ZIP,
ersetzt die drei installierten Prototyptreiber kontrolliert, prüft deren Laufzustand und wiederholt
Consumer-, Security- und Recovery-Inspektion. Bei fehlgeschlagener Treiberinstallation versucht er,
das vorherige lokale Treiberpaket wiederherzustellen.

Weiterhin extern oder rebootpflichtig:

1. Driver Verifier für genau die drei RC-Treiber mit kontrolliertem Neustart und Notfallreset.
2. Neustart-, Installations-, Update-, Rollback- und Recovery-Zyklen auf einem wiederherstellbaren
   Testsystem; der aktuelle nicht erhöhte Lauf verändert diese Zustände nicht.
3. Längerer interaktiver Fehlalarmtest, bei dem Browser, VPN, Spiele, Installer und Skripte wirklich
   verwendet werden. Das vorhandene Inventar allein beweist keine Kompatibilität.
4. HLK/WHCP. HVCI läuft und alle Submission-Artefakte sind vorhanden; auf diesem Rechner fehlen HLK
   Studio/Controller und ein Controller-Endpunkt.
5. Unabhängiges Kernelreview und Penetrationstest durch eine organisatorisch getrennte Stelle.
6. Partner-Center-Upload und Microsoft-Produktionssignatur.

Keiner dieser Punkte darf ohne Ergebnisartefakt als bestanden markiert werden.
