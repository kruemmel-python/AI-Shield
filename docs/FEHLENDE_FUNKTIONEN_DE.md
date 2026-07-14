# AI Shield: Noch auszuführende Produktnachweise

Stand: 15. Juli 2026, nach Abschluss des RC12-ZIP- und latenzbegrenzten Minifilter-Schutzpfads

## Noch auszuführende Produktnachweise

Der Start erfasst inzwischen automatisch Secure Boot/Testsigning, TPM, HVCI, Credential Guard,
Defender, Firewall, verwundbare-Treiber-Blockliste, ASR und Volumeverschluesselung. Er aendert diese
Windows-Einstellungen absichtlich nicht ungefragt; Aktivierung und Kompatibilitaet bleiben reale
Produktnachweise und Administratorentscheidungen.

Broker und Core werden inzwischen hash-verifiziert aus einem ACL-geschuetzten Program-Files-Pfad
ausgefuehrt. Eine transaktionale Defender-Baseline kann ASR, Network Protection, Controlled Folder
Access und PUA-Schutz im nicht blockierenden Auditmodus staffeln und vollstaendig zurueckrollen.

Die zusaetzlichen Enterprise-Bloecke sind implementiert: publisher-gepinnter Browser-Native-Host,
TLS-gepinnte WEF-Quelle, WDAC-Auditpolicy mit Event-3076-Auswertung, PowerShell-Metadatenforwarder
ohne Scripttext, transaktionale Firewallbaseline, nicht schreibender UAC-Assistent und rein
evidenzbasierte ASR-Empfehlungen. Externe Collector-, Extension-Store- und SOC-Endpunkte bleiben
deployment-spezifische Konfiguration und kein offener Produktcode.

Auch die lokalen Consumer-Betriebsfunktionen sind implementiert: MSI-Installation und vollständiger
Treiber-/Dienst-Rückbau, versteckter UI-Host nach UAC, Neustartfortsetzung, Edge-/Chrome-Sensor,
DPAPI-geschützter Dateityp-Schutz, isolierter Defender-/AMSI-/PDF-/ZIP-Downloadscanner,
Quarantäneworkflow sowie ein integrierter Viewer für lokale und exportierte AISHAD02-Dateien.
RC12 ergänzt eine budgetierte ZIP-/ZIP64-Tiefenanalyse und eine auf 250 ms begrenzte
Filter-Manager-Übergabe zwischen Minifilter und Broker. Die Inhaltsanalyse läuft getrennt;
Dateiöffnungen bleiben bis zum identitätsgebundenen Ergebnis gesperrt. Timeout, Portausfall,
Warteschlangenüberlauf und ungültige Antworten bleiben `pending`. Damit enthält diese Liste
keine bekannte, nur durch weiteren lokalen Produktcode schließbare
Schutzlücke; offen sind Nachweise, externe Vertrauensanker und deployment-spezifische Parameter.

RC8 ergänzte einen ACL-geschützten, inhaltsadressierten Recovery-Vault, Installationsbaseline,
Canary- und Änderungsserienerkennung, einen pro Prozess korrelierenden C++-Detektor,
Minifilter-/Broker-Echtzeitsignale, bestätigungspflichtige hashverifizierte Rücksicherung mit
Konfliktspeicher sowie externe Backups mit prüfbarem SHA-256-Manifest. Der automatisierte Test deckt
Snapshot, Erkennung, Plan, Restore und externe Backupprüfung ab. Eine echte WinRE-/Offline-
Systemdateiwiederherstellung und ein unveränderliches externes Ziel bleiben Produktnachweise und
deployment-spezifische Infrastruktur, keine gefahrlos automatisch aktivierbare lokale Funktion.

RC9 ergänzte Content-Policy v3, zehn einzeln steuerbare Dateigruppen, die standardmäßig aktive
Freigabeschranke, sichtbare UI-Benachrichtigungen und lokalisierte Quarantänegründe. Der reale
Integrationstest weist nach, dass auch eine sauber geprüfte Bilddatei vor dem Öffnen freigegeben
werden muss. Damit ist die zuvor beobachtete automatische Freigabe von Medien im lokalen
Produktcode geschlossen. Das damals noch offene Kernel-Pending wurde mit RC12 implementiert und
nach einem Desktop-Latenzbefund in eine 250-ms-Übergabe mit asynchronem Analyse-Worker gehärtet;
Kompatibilitäts- und Dauertests bleiben Produktnachweise.

RC10 ergänzt den automatisch gestarteten Tray-Agenten, die UI-Einzelinstanz und Close-to-Tray.
Minimieren und `X` beenden weder UI-Prozess noch Schutzkern; der Tray-Doppelklick stellt dieselbe
PID ohne weitere UAC-Abfrage wieder her. Damit ist der lokale Hintergrundbetrieb als Produktcode
geschlossen und verbleibt nur als Kompatibilitäts- und Dauertestgegenstand.

RC11 ergänzt Content-Policy v4, die Kategorie für unbekannte und spezialisierte Formate, einen
universellen Magic-/Namens-/Polyglot-Preflight, WAV-/ZIP-Härtung, SHA-256-Provenienz über dasselbe
gesperrte Datei-Handle und einen isolierten Minimalworker. Der WFP-Treiber blockiert dessen gesamte
IPv4-/IPv6-Kommunikation. Nicht vorhandene Spezialparser führen damit nicht mehr zur automatischen
Positivfreigabe, sondern zur konservativen Freigabeschranke. Formatspezifische Vollparser und CDR
für jede Spezialdomäne bleiben Qualitätsausbau, nicht still offene Umgehung.

Der lokale Dateisystempfad wurde zusätzlich gegen nicht auflösbare Junctions und andere Reparse
Points gehärtet. Der automatisierte Test enthält dafür ein negatives Junction-Szenario. Auf dem
Referenzrechner wurde eine reale Baseline mit 13.353 Dateien und null Übersprüngen abgeschlossen.
Diese Ergebnisse schließen den lokalen Funktionspfad, ersetzen aber weiterhin keine Vollplatten-,
Stromausfall- oder Langzeitqualifikation.

Credential Guard ist neustartbereit vorbereitet, Defender Cloud Protection und lokales PowerShell-
Logging sind aktiv. Tamper Protection bleibt eine Windows-Security-/Intune-Verwaltungsfunktion.
BitLocker wartet absichtlich auf ein externes Recovery-Ziel; Browser, WEF und PowerShell-Forwarding
warten auf reale externe IDs, URLs und Zertifikatpins. ASR-Enforcement wartet auf die definierte
Mindestmenge repraesentativer Auditereignisse.

- Microsoft Partner Center, EV-Identität, Inf2Cat/CAB-Abnahme, WHCP/HLK und Microsoft-Signierung.
- Reale Secure-Boot-, HVCI- und Driver-Verifier-Läufe auf jeder unterstützten Windows-Version.
- Vollplatten-, Stromausfall-, Neustart-, Upgrade-, 24-Stunden- und 30-Tage-Dauertests im Labor.
- Kompatibilitätsmatrix für Defender, VPNs, Browser, Datenbanken und Entwicklungswerkzeuge.
- Repräsentative Fehlalarm-, Last- und Angriffskorpusmessungen.
- Unabhängiges Threat Modeling, Kernel-Code-Review, Penetrationstest, Red Team und Datenschutzprüfung.
- Hyper-V-Tier-2 und Sovereign Mode bleiben getrennte langfristige Architektur-Tracks.

Kein Skript ersetzt einen realen Nachweis. Diese Gates dürfen erst nach protokolliertem Laborlauf als
bestanden markiert werden.
