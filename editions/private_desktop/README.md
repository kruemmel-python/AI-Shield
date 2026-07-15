# AI Shield Private Desktop

Release Candidate: `2.0.0-rc.13`. ABI-, Policy- und Funktionsumfang sind durch
[`RELEASE_CONTRACT.json`](RELEASE_CONTRACT.json) eingefroren. Änderungen an sicherheitsrelevanten
Verträgen werden von `validate_release_freeze.ps1` abgelehnt, bis ein bewusst neuer Vertrag erstellt
wird.

RC13 ergänzt eine direkte, transaktionale Quarantänefreigabe über Broker und Minifilter. Das Ziel
muss auf demselben Volume wie der Quarantänespeicher liegen; bei Identitäts- oder Kernelproblemen
wird die Datei automatisch zurückgerollt.

Ein installierbares RC-Paket darf nur aus dem frisch gebauten und anschließend testsignierten
Treiber-Staging erzeugt werden. `tools\complete_private_rc_admin.ps1` führt dieses erhöhte Gate aus;
der Packager lehnt unsignierte Treiber ab.

## Ziel dieser Edition

Diese Edition richtet sich ausschließlich an private Windows-Nutzer mit einem einzelnen PC. Sie
verwendet die gemeinsame AI-Shield-Sicherheitsengine, enthält im Bedien- und Auslieferungspaket aber
keine zentralen Collector-, Flottenverwaltungs- oder SOC-Funktionen. Ein Webserver, Test-Backend oder
freier Listener-Port ist für den normalen Schutzbetrieb nicht erforderlich.

Der Standardstart aktiviert:

- IPv4-/IPv6-WFP-Telemetrie und den lokalen Wurm-Egress-Schutz;
- Minifilter-Provenance, synchrones Pending-Protokoll und Quarantäneschutz;
- ProcessGuard gegen ausgewählte riskante Prozessketten;
- Broker, Core-Überwachung und signierte lokale Policy;
- Blockierung von Ausführung aus Quarantäne und Benutzer-Temp;
- Regeln gegen riskante Skriptbefehle und Office-Kindprozesse.

Die Installation aktiviert außerdem die Windows-Firewall mit `Inbound=Block` und `Outbound=Allow`
sowie Microsoft-Defender-, ASR-, Network-Protection- und Controlled-Folder-Access-Regeln im
Auditmodus. Vorherige Einstellungen werden gesichert und bei Deinstallation nur dann zurückgerollt,
wenn diese Edition die Transaktion selbst angelegt hat.

## Wichtige Prototypgrenze

Die aktuellen Treiber sind lokal testsigniert. Deshalb funktioniert diese Ausgabe nur mit
deaktiviertem Secure Boot und aktiviertem Windows-TESTSIGNING. Das ist für einen gewöhnlichen
privaten Produktiv-PC kein empfohlener Dauerzustand. Vor einer öffentlichen Endanwenderfreigabe
werden von Microsoft signierte Treiber benötigt; anschließend müssen Secure Boot aktiviert und
TESTSIGNING deaktiviert werden.

Für den lokalen Prototyptest muss zuerst im UEFI-Setup Secure Boot deaktiviert werden. Danach in
einer als Administrator gestarteten PowerShell ausführen und Windows neu starten:

```powershell
bcdedit.exe /set testsigning on
Restart-Computer
```

Falls Windows meldet, dass der Wert durch die Richtlinie für sicheres Starten geschützt ist, ist
Secure Boot noch aktiv. AI Shield umgeht diese Sperre nicht und ändert die Bootkonfiguration nicht
automatisch.

## Bedienung

1. Bevorzugt `AI_Shield_Private_Desktop.msi` doppelt anklicken. Alternativ das vollständige ZIP-Paket
   in einen lokalen Ordner entpacken.
2. `Installieren.cmd` doppelt anklicken und die UAC-Abfrage bestätigen.
   Nach der Installation startet die grafische Oberfläche automatisch und ist danach im Startmenü
   unter **AI Shield Private Desktop** erreichbar. Alternativ öffnet `AI_Shield_UI.cmd` die UI.
   Zusätzlich wird der Tray-Agent für jede Windows-Anmeldung eingerichtet.
3. Nach erfolgreicher Installation mit `Status_anzeigen.cmd` prüfen, dass drei Treiber sowie Broker
   und Core laufen.
4. `Schutz_starten.cmd` aktiviert den Schutz nach einem manuellen Stopp erneut.
5. `Schutz_beenden.cmd` setzt die Policy in den Auditmodus und stoppt Sensoren und Broker.
6. `Deinstallieren.cmd` entfernt die Edition und rollt ihre eigenen Firewall-/Defender-Baselines
   zurück. Audit- und Quarantänedaten bleiben standardmäßig erhalten.

Der MSI-Eintrag unter **Installierte Apps** führt denselben vollständigen Rückbau aus: Browser-Host,
Broker, Core und alle drei Kernel-Treiber werden entfernt; von AI Shield angelegte Baselines werden
transaktional zurückgerollt. Details und Befehle stehen in
`platform\windows\msi\README_DE.md` des Entwicklerpakets.

Die Oberfläche bietet sechs Bereiche für Status, Schutzschalter, Auditprüfung/-export, Quarantäne,
Ransomware-Wiederherstellung und Windows-Sicherheit. HVCI und Credential Guard zeigen bei notwendigen Systemänderungen eine
Neustartschaltfläche. Die Erstinstallation erzeugt genau dann eine Recovery-Baseline für persönliche
Ordner, wenn noch kein Snapshot existiert. Weitere Snapshots, externe Sicherungen und jede
Rücksicherung sind bewusste Benutzeraktionen. Nach Bestätigung startet Windows neu; bei der nächsten Anmeldung öffnet eine
einmalige erhöhte Aufgabe die UI wieder und liest den wirksamen Zustand ein. Details stehen in
[`ui\README.md`](ui/README.md).

Die drei Kernel-Treiber sowie Broker und Core laufen als automatisch gestartete Windows-Dienste
bereits vor einer Benutzeranmeldung und unabhängig von UI oder Tray. Der Tray-Agent zeigt diesen
Zustand im Windows-Infobereich an. Doppelklick öffnet die UI; das Kontextmenü kann den Status
aktualisieren, die Schutzdienste erhöht neu starten oder die Windows-Diensteverwaltung öffnen.
**Tray-Agent beenden** entfernt nur das Symbol der aktuellen Anmeldung und beendet keinen Schutz.
Der Schalter **AI Shield im Infobereich** verwaltet den automatischen Start bei der Anmeldung.
Minimieren oder `X` verbergen die UI vollständig aus der Taskleiste. Der Tray-Doppelklick stellt
dieselbe laufende Einzelinstanz ohne erneute UAC-Abfrage wieder her.

Der signierte Native-Messaging-Host für Edge und Chrome wird standardmäßig installiert. Die
Erweiterung benötigt ohne veröffentlichte HTTPS-Updatequelle je Browser einmalig den von der UI
geführten Schritt **Entpackte Erweiterung laden**. Übertragen werden nur Schema, Hostname, Port,
Pfadlänge, Query-Vorhandensein, Navigationsart und Downloadstatus; vollständige URLs, Inhalte,
Formulardaten und Cookies werden nicht aufgezeichnet.

Nach der Deinstallation kann der Testmodus in einer erhöhten PowerShell beendet werden:

```powershell
bcdedit.exe /set testsigning off
Restart-Computer
```

Anschließend Secure Boot im UEFI-Setup wieder aktivieren und den Status mit
`Confirm-SecureBootUEFI` prüfen. Diese Rückkehr zum normalen Windows-Vertrauensmodell ist für einen
privaten Alltags-PC wichtig.

Die Private-Desktop-Standardkonfiguration blockiert direkte Programmstarts aus `Downloads` sowie
Interpreterstarts, deren Befehlszeile ein Skript aus `Downloads` referenziert. Erfasst werden unter
anderem PowerShell, CMD, WSH, MSHTA, Bash, WSL, Python, Node, Perl, Ruby, PHP, Java, .NET,
MSIExec, Rundll32, Regsvr32 und weitere Windows-Systemlauncher. Alle nach dem Brokerstart
neu angelegten oder geänderten Downloads werden unabhängig vom Vorhandensein eines
Mark-of-the-Web unter festgehaltener Dateiidentität
in einem zeitlich begrenzten, isolierten Inhaltscanner mit Microsoft Defender/AMSI geprüft. PDF- und
ZIP- und RIFF/WAV-Inhalte erhalten dort eine lokale Strukturprüfung; aktive oder fehlerhafte PDFs,
gefährliche/verschlüsselte Archive, Malwarefunde und
nicht prüfbare risikoreiche Parserformate werden in die AI-Shield-Quarantäne verschoben. Saubere
Bilder, Medien und Dokumente werden bei aktiver Freigabeschranke ebenfalls gesichert und bleiben
nach einer begründeten Freigabe benutzbar. Die Download-Härtung und weitere Optionen sind in der UI
einzeln schaltbar und zusätzlich per PowerShell verfügbar:

Unter **Schutzfunktionen > Dateityp-Schutz** lassen sich Dokumente, Archive, Bilder, Audio, Video,
Webdateien, Programme/Installer, Windows-Skripte, Entwickler-/Shell-Skripte sowie Verknüpfungen und
Systemaktionen separat ein- oder ausschalten. Policy v4 ergänzt **Unbekannte und Spezialformate**,
damit unbekannte Endungen, Modelle, Firmware-, CAD/GIS-, Plugin- und Mod-Container nicht ungeprüft
durchfallen. Die Ausführungsgruppen umfassen unter anderem
`EXE`, `MSI`, `MSIX`, `APPX`, `BAT`, `CMD`, `PS1`, `PSM1`, `VBS`, `JS`, `WSF`, `HTA`, `SH`, `PY`,
`JAR`, `LNK`, `URL`, `REG`, `INF` und `CHM`. Ein aktiver Schalter bedeutet Inhaltsprüfung. Mit der
standardmäßig aktiven Option **Freigabe vor dem Öffnen erzwingen** werden auch sauber gescannte
Dateien dieser Gruppe zunächst in die Quarantäne verschoben. Die UI meldet neue Downloads sichtbar;
erst eine begründete Freigabe stellt die Datei wieder bereit. Ein deaktivierter Dateitypschalter
gibt diese Gruppe ohne AI-Shield-Inhaltsprüfung frei. Die Option
**Bei Scanfehler sicher quarantänisieren** bestimmt das Fail-closed-Verhalten. Diese Richtlinie wird
atomar und mit DPAPI-Machine-Schutz gespeichert und vom Broker ohne Neustart neu geladen.
Bestehende Policy-v1-/v2-/v3-Dateien werden auf Policy v4 migriert. Die Ausführungsgruppen,
**Unbekannte und Spezialformate** und die Freigabeschranke sind beim Upgrade zunächst
eingeschaltet. Der globale Schalter **Downloads härten** bleibt die
zusätzliche ProcessGuard-Sperre für direkte und interpretergestützte Starts aus `Downloads`.

```powershell
powershell -ExecutionPolicy Bypass -File .\start_private_desktop.ps1 -HardenDownloads
powershell -ExecutionPolicy Bypass -File .\start_private_desktop.ps1 -StrictBrowser
powershell -ExecutionPolicy Bypass -File .\start_private_desktop.ps1 -BlockUnsolicitedInbound
```

Diese Optionen können legitime Installations-, Browser-, VPN-, Spiele- oder Heimnetzfunktionen
beeinträchtigen und müssen einzeln getestet werden.

## Schutzgrenzen

AI Shield ergänzt Defender, Windows-Firewall, Updates, UAC, BitLocker und sichere Backups. Die
Kernel-/Hardware-Baseline reduziert Angriffsflächen durch HVCI/VBS, die Microsoft-Blockliste
verwundbarer Treiber, TPM-Bindung und auf geeigneter Produktionshardware durch Secure Launch und
Kernel-DMA-Anforderungen. Sie kann eine bereits kompromittierte CPU, manipulierte Firmware oder
einen unbekannten Kernel-Fehler nicht mathematisch ausschließen.

Belastbare Produktformulierung: **Die Schutzfunktionen sind real und wirksam und decken alle von der
freigegebenen Policy definierten Netzwerk-, Prozess-, Datei-, Browser- und Windows-Härtungsbereiche
ab.** Eine Aussage über 100 Prozent aller denkbaren Angriffsvektoren wäre weder testbar noch
seriös; stattdessen weist der Posture-Bericht jede aktive, fehlende oder hardwareabhängige
Gegenmaßnahme einzeln nach.

Die technische Einzelplatzbewertung steht in
[`SOFTWAREBEWERTUNG_PRIVAT.md`](SOFTWAREBEWERTUNG_PRIVAT.md).
Der aktuelle Release-Candidate-Nachweis und seine noch offenen Gates stehen in
[`QUALIFIKATIONSSTATUS.md`](QUALIFIKATIONSSTATUS.md).
