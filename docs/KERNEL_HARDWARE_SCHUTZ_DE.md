# Kernel- und Hardware-Schutz

Stand: 14. Juli 2026

AI Shield behandelt Kernel- und Hardwareangriffe als mehrschichtiges Risiko. Ein eigener Treiber
kann keinen unbekannten Fehler im Windows-Kernel reparieren und keine bereits manipulierte CPU oder
Firmware vertrauenswürdig machen. Er kann jedoch die nutzbaren Angriffspfade verkleinern,
Manipulationen korrelieren und Windows-Hardwarewurzeln konsequent verwenden.

## Implementierte Gegenmaßnahmen

- HVCI/VBS trennt Codeintegritätsentscheidungen vom normalen Kernel.
- Die Microsoft-Blockliste verwundbarer Treiber erschwert Bring-Your-Own-Vulnerable-Driver-Angriffe.
- Der nicht exportierbare TPM-Anker bindet lokale Verträge und Nachweise an den Rechner.
- System Guard Secure Launch wird nur auf Secure-Boot-/TPM-fähiger Produktionshardware aktiviert.
- Die DMA-Plattformanforderung wird nur gesetzt, wenn Windows Kernel-DMA-Schutz meldet.
- Posture erfasst Secure Boot, Testsigning, TPM, HVCI, DMA, Secure Launch, SMM-Messung,
  Kernel-Stackschutz und BitLocker einzeln.
- Die Desktop-UI verwaltet die Baseline transaktional und bietet Neustart-Wiederaufnahme.
- Der Enterprise-Strict-Start aktiviert dieselbe gemeinsame Baseline.

## Bewusste Sicherheitsgrenzen

Secure Launch, SMM-Messung und Kernel-DMA-Schutz benötigen passende CPU-, Chipsatz-, UEFI- und
Windows-Unterstützung. AI Shield setzt diese Funktionen nicht blind, wenn die Plattform sie nicht
meldet. BitLocker wird nicht ohne extern geprüften Wiederherstellungsschlüssel automatisch
gestartet. Während der Prototyp testsignierte Treiber verwendet, bleibt Secure Boot deaktiviert;
damit ist die vollständige hardwareverwurzelte Startkette noch nicht erreichbar.

Kein lokales Produkt kann 100 Prozent unbekannter Kernel-, Firmware-, Supply-Chain- und
Siliziumangriffe garantieren. Der überprüfbare Anspruch lautet deshalb: Alle freigegebenen
Sensorbereiche und Härtungsregeln werden durchgesetzt, ihr Laufzeitstatus wird gemessen, und nicht
verfügbare Hardwareeigenschaften werden sichtbar als fehlend ausgewiesen.
