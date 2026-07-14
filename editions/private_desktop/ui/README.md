# Grafische Oberfläche

`AI_Shield_UI.cmd` öffnet die lokale WPF-Oberfläche. Sie fordert Administratorrechte über UAC an;
nach der Bestätigung bleibt der PowerShell-Konsolenhost unsichtbar und nur die WPF-Oberfläche wird angezeigt.
weil Treiber, Dienste, signierte Policies und Windows-Sicherheitsfunktionen nicht mit normalen
Benutzerrechten verändert werden dürfen.

Die Oberfläche enthält sechs Ansichten:

- **Übersicht:** Zustand der drei Kernel-Treiber, des Brokers und des Core-Dienstes;
- **Schutzfunktionen:** Kernschutz sowie optionale Download-, Browser- und Inbound-Regeln;
- **Audit:** vorhandene Auditdateien anzeigen, kryptografisch prüfen und exportieren;
- **Quarantäne:** isolierte Dateien anzeigen und nur mit Zielpfad und Begründung freigeben;
- **Wiederherstellung:** Baseline-Snapshots, Ransomware-Prüfung, Vorfallplan, bestätigte
  Rücksicherung und externe hashmanifestierte Sicherung;
- **Windows-Sicherheit:** HVCI, Credential Guard, Firewall- und Defender-Auditbaseline.

Der separate Tray-Agent unter `tray\start_tray_agent.ps1` läuft ohne Administratorrechte in der
interaktiven Benutzersitzung. Er überwacht die fünf Windows-Komponenten, zeigt Zustandsänderungen im
Infobereich und öffnet die erhöhte UI auf Doppelklick. Der Schutzkern läuft davon unabhängig als
Windows-Dienst beziehungsweise Kernel-Treiber. Installation und UI verwalten den maschinenweiten
Anmeldeautostart über `tray\manage_tray_agent.ps1`; die Deinstallation entfernt ihn wieder.
Minimieren und das Schließen über `X` verbergen die UI und entfernen sie aus der Taskleiste. Die
bereits laufende UI bleibt als Einzelinstanz erhalten. Ein Doppelklick auf das Tray-Symbol signalisiert
dieser Instanz, wieder sichtbar zu werden; dadurch entsteht weder ein zweites Fenster noch eine neue
UAC-Abfrage. Tray-Agent, UI und privilegierter Schutzkern bleiben getrennte Prozesse.

HVCI, Credential Guard und die Kernel-/Hardware-Baseline werden transaktional verwaltet. Die UI sichert den vorherigen Registry-
Zustand und deaktiviert keine Einstellung, die sie nicht selbst aktiviert hat. Wenn Windows einen
Neustart benötigt, erscheint **Jetzt neu starten**. Vor dem Neustart wird eine einmalige, erhöhte
Anmeldeaufgabe registriert. Nach der Anmeldung öffnet sie die Oberfläche erneut, liest den
tatsächlichen Laufzeitstatus ein und entfernt sich selbst.

Firewall- und Defender-Schalter verwenden die vorhandenen Backup-/Rollback-Skripte. Die
Defender-Baseline bleibt bewusst im Auditmodus; die UI behauptet keine Durchsetzung, solange keine
Kompatibilitätsmessung und bewusste Freigabe für den Blockiermodus vorliegen.

Die Kernel-/Hardware-Baseline aktiviert VBS/HVCI und die Microsoft-Blockliste verwundbarer Treiber.
Secure Launch und die DMA-Plattformanforderung werden nur vorbereitet, wenn Windows aktives Secure
Boot, TPM und die jeweilige Hardwarefähigkeit meldet. BitLocker bleibt ein Assistent, weil der
Wiederherstellungsschlüssel vor Verschlüsselungsbeginn außerhalb des Rechners geprüft werden muss.

Der Edge-/Chrome-Sensor wird mit einem Authenticode-signierten Native-Messaging-Host und einer
stabilen lokalen Erweiterungs-ID bereitgestellt. Chromium-Browser erlauben ohne Store- oder
HTTPS-Updatequelle keine lautlose Endnutzerinstallation. Deshalb öffnet die UI die jeweilige
Erweiterungsseite, kopiert den geschützten Erweiterungsordner in die Zwischenablage und führt durch
den einmaligen Schritt **Entpackte Erweiterung laden**. Danach zeigt die UI den Zeitpunkt des
letzten tatsächlich empfangenen Browserereignisses an. Die Statusanzeige unterscheidet dabei
zwischen **Host installiert**, **Erweiterung geladen** und **Verbunden**. Im Edge-Auswahldialog muss
der Ordner selbst mit **Ordner auswählen** bestätigt werden; `manifest.json` darf nicht als einzelne
Datei geöffnet werden.

Die statische UI-Vertragsprüfung kann ohne Systemänderung ausgeführt werden:

```powershell
powershell -NoProfile -STA -File .\ui\verify_ui_contract.ps1
```
