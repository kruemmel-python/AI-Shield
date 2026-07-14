# AI Shield RC10 Release- und Installationsnachweis

Stand: 14. Juli 2026, Release Candidate `2.0.0-rc.10`

## Umfang

RC10 erweitert den verifizierten RC9-Downloadschutz um einen dauerhaft angemeldeten Desktop-
Tray-Agenten. Die drei Kernel-Treiber, `AIShieldBroker` und `AIShieldCore` starten weiterhin
unabhängig von UI und Tray als Windows-Systemkomponenten. Der Tray-Agent zeigt ihren Zustand im
Windows-Infobereich, startet bei jeder Benutzeranmeldung und öffnet die administrative UI.

Die UI ist eine benutzerspezifische Einzelinstanz. Minimieren oder `X` entfernt das Fenster aus der
Taskleiste, ohne UI-Prozess oder Schutzkern zu beenden. Ein Tray-Doppelklick aktiviert dieselbe PID
über einen atomaren, gegen PID-Reuse abgesicherten Instanzvertrag unter `%LOCALAPPDATA%`; eine
weitere UAC-Abfrage und parallele UI-Fenster entfallen.

## Verifizierte lokale Prüfungen

| Prüfung | Ergebnis |
|---|---|
| Release-CTest | 14 von 14 bestanden |
| Debug-CTest | 14 von 14 bestanden |
| UI-Vertrag | 61 Controls, 6 Ansichten, persistenter WPF-Dispatcher |
| Tray-Vertrag | Einzelinstanz, Autostart und Fünf-Komponenten-Status bestanden |
| Realer Minimierungstest | Fenster verborgen, Prozess aktiv, gleiche PID wiederhergestellt |
| Installierter Schutzstatus | WFP, Minifilter, ProcessGuard, Broker und Core aktiv |
| Release-Freeze | gültig für `2.0.0-rc.10` |
| Desktop-Paket | Manifest und sichere ZIP-Pfade geprüft |
| MSI | WiX-Build und lokale Authenticode-Testsignatur gültig |

Beobachtete Kernausgabe des UI-Laufzeittests:

```text
hidden=True
process_alive=True
same_pid=True
restored=True
```

## Release-Artefakte

Der GitHub-Release `v2.0.0-rc.10` enthält:

- `AI_Shield_Private_Desktop.zip`
- `AI_Shield_Private_Desktop_2.0.0-rc.10_x64.msi`
- `AI_Shield_Developer_ABI2.zip`
- `AI_Shield_Developer_Full.zip`
- `SHA256SUMS.txt`

Die konkreten äußeren SHA-256-Werte stehen in `SHA256SUMS.txt`. Desktop- und Developer-Full-Paket
enthalten zusätzlich Dateimanifeste. Der Releasevertrag friert ABI, Policy und sicherheitsrelevante
RC10-Dateien mit SHA-256 ein.

## Signierungs- und Freigabegrenze

MSI und Treiber sind mit `CN=AI Shield Prototype Test Signing` lokal testsigniert. Das ist keine
Microsoft-Produktionstreibersignatur. Die Treiberinstallation erfordert deshalb weiterhin ein
kontrolliertes Testsystem mit deaktiviertem Secure Boot und aktiviertem Windows-`TESTSIGNING`.
Microsoft-Submission, HLK/WHCP, rebootpflichtige HVCI-/Driver-Verifier-Läufe, Langzeit- und
Kompatibilitätsmessungen sowie ein unabhängiger Security Review bleiben externe Produktnachweise.
