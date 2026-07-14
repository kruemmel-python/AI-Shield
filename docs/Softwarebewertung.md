# Softwarebewertung: AI Shield 2.0

Stand: 14. Juli 2026, bewertet wird Release Candidate `2.0.0-rc.12`

Nachtrag zum verifizierten RC8-Stand: Die Recovery-Erstbaseline wurde auf dem Referenzrechner mit
13.353 Dateien und null Übersprüngen abgeschlossen. Nicht auflösbare Junctions und Reparse Points
werden nicht verfolgt und sind durch einen negativen Integrationstest abgedeckt. Alle zwölf
CTest-Ziele bestanden. Diese Evidenz verbessert die lokale Funktionsreife, ersetzt jedoch keine
Langzeit-, Vollplatten-, Stromausfall- oder unabhängige Sicherheitsqualifikation.

RC9 ergänzt die praktisch relevante Download-Freigabeschranke: Saubere Dateien aktiver Gruppen
werden nicht mehr automatisch als vertrauenswürdig behandelt, sondern bis zur begründeten
Freigabe quarantänisiert und in der UI gemeldet. Der reale Integrationstest für ein sauberes Bild
und eine aktive PDF ist Bestandteil des Release-Nachweises.

RC10 ergänzt den für Endanwender notwendigen Hintergrundbetrieb: Tray-Autostart, Status der fünf
Schutzkomponenten, UI-Einzelinstanz und Close-to-Tray wurden implementiert und real geprüft.

RC11 ergänzt die universelle Datei-Preflight-Kette, die unbekannte Formate nicht mehr umgeht,
Dateiidentität und SHA-256 über dasselbe gesperrte Handle bindet und den isolierten Scanner durch
Job-Limits sowie eine WFP-Netzwerksperre begrenzt. Die Regressionen umfassen 15 Release- und
Debug-CTest-Ziele sowie reale erhöhte Downloadtests.

## Gegenstand und Bewertungsrahmen

AI Shield 2.0 ist ein gehärteter Windows-Sicherheitsprototyp, der Netzwerk-, Datei-, Prozess- und
Windows-Sicherheitsereignisse zusammenführt, bewertet und teilweise direkt durchsetzt. Das Projekt
verbindet drei Kernel-Treiber mit LocalSystem-Diensten, einem gemeinsamen C++-Kern, einem lokalen
Administrationskanal und mehreren Windows-Härtungsintegrationen.

Diese Bewertung berichtigt die zuvor vorgelegte, stark werbliche Softwarebewertung. Sie stützt sich
auf den Quellcode, die Projektdokumentation und die im Projekt festgehaltenen lokalen Build-, Test-
und Installationsnachweise mit Stand 14. Juli 2026. Sie ist weder ein unabhängiger Penetrationstest
noch eine Microsoft-Zertifizierung oder eine Freigabe für den Produktivbetrieb.

| Merkmal | Bewerteter Stand |
|---|---|
| Produktklasse | Hostbasierter Windows-Sicherheitsprototyp |
| Kernel-Transport | Eingefrorener ABI 1.2 |
| Interne Ereigniskorrelation | AISHAD02 / ABI 2.0 |
| Lokale Plattform | Windows x64, Testsigning-Umgebung |
| Automatisierte Tests | 16 CTest-Ziele, in Release und Debug erfolgreich |
| Treiber | WFP, Minifilter und ProcessGuard lokal testsigniert und lauffähig |
| Produktfreigabe | Nicht erteilt |

## Kurzurteil

AI Shield ist kein fertiges Enterprise-Sicherheitsprodukt und kein universeller Schutz gegen alle
Angriffe. Es ist jedoch ein technisch umfangreicher und ernstzunehmender Prototyp mit realen
Kernel-/User-Mode-Grenzen, authentisierten Ereignissen, korrelierter Auditierung, gehärteter
Quarantäne und einer breiten Windows-Integrationsbasis.

Die stärkste Leistung des Projekts ist die zusammenhängende Architektur: Sensordaten werden nicht
nur gesammelt, sondern über stabile Identitäten mit Policy-, Modell-, Prozess-, Datei- und
Netzwerkobjekten verbunden. Mehrere Schutzpfade besitzen echte Durchsetzungsmechanismen. Die größte
Schwäche liegt nicht in der Menge des vorhandenen Codes, sondern im fehlenden externen
Produktnachweis. Microsoft-signierte Treiber, HLK/WHCP, Langzeit- und Neustartprüfungen,
Kompatibilitätsmessungen, Fehlalarmkorpora und unabhängige Sicherheitsprüfungen stehen noch aus.

**Gesamtbewertung: 6,8 von 10 - fortgeschrittener Sicherheitsprototyp, noch kein produktionsreifes
Enterprise-Produkt.**

## Bewertungsprofil

| Bereich | Wertung | Begründung |
|---|---:|---|
| Architektur und Modulgrenzen | 8,0/10 | Klare Trennung von Kerneltransport, Broker, Core, Policy, Audit und Administration |
| Kernel-/User-Mode-Vertrag | 7,5/10 | Versionierter ABI 1.2 mit validierter Übersetzung in ABI 2.0; externe Treiberqualifikation fehlt |
| Datei- und Prozessschutz | 7,8/10 | Handle-basierte Quarantäne, isolierter Downloadscanner, Dateityp-Policy und konkrete ProcessGuard-Regeln; Feldnachweise fehlen |
| Kryptografie und Audit | 7,0/10 | HMAC, SHA-256-Kette, DPAPI und Rotation sind vorhanden; kein externer Unbestreitbarkeitsnachweis |
| Netzwerkabdeckung | 6,5/10 | IPv4/IPv6-WFP-Telemetrie und Portregeln; keine allgemeine Entschlüsselung verschlüsselter Inhalte |
| Windows- und SOC-Integration | 5,5/10 | Viele Adapter und Assistenten; mehrere Integrationen benötigen reale Unternehmensendpunkte |
| Betriebsreife und Nachweise | 4,5/10 | Gute lokale Tests, aber keine Microsoft-Freigabe, belastbare Feldmessung oder unabhängige Prüfung |

Die Gesamtwertung berücksichtigt nicht nur implementierte Funktionen, sondern ebenso den
Nachweisgrad. Eine hohe Quellcodeabdeckung kann fehlende Feld-, Sicherheits- und
Zertifizierungsnachweise nicht ersetzen.

## Tatsächlich implementierte Schutzarchitektur

### Kernel- und Ereignispipeline

Die drei Windows-Treiber liefern getrennte Beobachtungs- und Durchsetzungspfade:

- Der WFP-Treiber erfasst IPv4- und IPv6-Flows für TCP und UDP und kann definierte ausgehende
  Verbindungen sowie transparente Umleitungsfälle behandeln.
- Der Minifilter liefert Dateiereignisse und Identitätsmerkmale für Provenance und Quarantäne.
- ProcessGuard beobachtet Prozessstarts und setzt Regeln für riskante Startorte,
  Office-Kindprozesse, Skriptinterpreter, LOLBins sowie ausgewählte Credential-Access- und
  Persistenzmuster um.

Der Kerneltransport verwendet den eingefrorenen ABI 1.2. Der Broker validiert Sequenzen, Größen,
Versionen und HMACs und übersetzt akzeptierte Ereignisse in das interne AISHAD02-/ABI-2.0-Modell.
Flow-, Datei-, Provenance-, Prozess-, Parent-, Policy- und Modell-IDs können dadurch im
Kausalgraphen, Auditpfad, Incident-Paket und Replay erhalten bleiben.

### Quarantäne und TOCTOU-Härtung

Die Quarantäne ist technisch deutlich stärker als ein gewöhnliches Verschieben nach Dateipfad. Der
Broker öffnet das Dateiobjekt, verwirft Reparse Points, Mehrfach-Hardlinks und unbekannte Alternate
Data Streams, prüft Volume- und Dateiidentität, hasht über das geöffnete Handle und führt eine
handle-relative Umbenennung auf demselben Volume aus. Größenstabilität und Authenticode-Vertrauen
werden ebenfalls berücksichtigt.

Diese Aussage gilt aber nur für den konkret implementierten Aufnahmebereich: neu geänderte Dateien
in Benutzer-Downloads und lokalem Temp, maximal 256 MiB und Internet-Provenance über Mark-of-the-Web
Zone 3 oder 4. Dokumente, Archive, Bilder, Audio, Video und Webdateien besitzen inzwischen getrennte
Policygruppen und eine isolierte Inhaltsprüfung; Netzlaufwerke, Dateien ohne Internet-Provenance und
jeder denkbare Schreibpfad werden damit nicht vollständig abgedeckt.

### Isolation und Parser

Parserprozesse können in einem AppContainer ohne Fähigkeiten gestartet werden. Job Objects begrenzen
Prozesszahl und Speicher und beenden die Gruppe bei definierten Fehlerfällen. Der dauerhafte Pool
verwendet einen privaten, zugriffsbeschränkten Named-Pipe-Kanal, eine begrenzte Ergebnisgröße und
einen Deadline-Wächter.

Das ist eine reale Isolationsschicht, aber kein Beweis, dass jeder Parser-Exploit folgenlos bleibt.
Dafür fehlen unter anderem umfangreiche Exploitkorpora, Langzeitmessungen und eine unabhängige
Bewertung der Sandboxgrenzen.

### Schlüssel, Policy und Audit

Ereignisse werden mit HMAC-SHA-256 authentisiert; der Vergleich des MAC erfolgt zeitkonstant. Der
lokale Laufzeitschlüssel ist über DPAPI im Maschinenkontext geschützt und besitzt Rotation,
Recovery-Slot und Upgrade-Migration. Eine optionale TPM-Bindung über den Microsoft Platform Crypto
Provider ist vorhanden.

Policy-Aktivierung verwendet signierte Konfiguration, monotone Sicherheitsversionen, atomare
Aktivierung und einen geprüften Rollbackpfad. Auditdaten werden im AISHAD02-Format in einer
SHA-256-Hashkette gespeichert und können offline überprüft, exportiert und wieder eingelesen werden.
Die Private-Desktop-UI besitzt dafür einen integrierten Viewer mit Integritätsprüfung, Filter und
Anzeige der ABI-2.0-Korrelationsfelder.

Die lokale Hashkette ist manipulationsanzeigend, aber nicht allein unbestreitbar. Ein Angreifer mit
ausreichenden lokalen Rechten könnte Daten und lokale Vertrauensanker gemeinsam angreifen. Für eine
stärkere Beweiskette müssen Auditdaten zeitnah an ein externes, gepinntes und getrennt verwaltetes
Ziel übertragen oder extern verankert werden.

### Netzwerk- und Webschutz

WFP erfasst systemweit Metadaten für IPv4 und IPv6. Die Auswertung umfasst unter anderem
IPv6-Extension-Header, Fragmentierung, ICMPv6 und QUIC-Long-Header-Metadaten. Ein sicherer
Standardmodus sperrt ausgewählte typische Wurm- und Lateral-Movement-Zielports; ein strengerer Modus
muss bewusst aktiviert und mit Allowlisten abgestimmt werden.

Der HTTP-Gatewaypfad analysiert HTTP-Anfragen, Parsergrenzen und erkannte Risikomuster. Er ist jedoch
kein universeller transparenter Inhaltsfilter für HTTPS, HTTP/3 oder beliebige verschlüsselte
Anwendungsprotokolle. WFP sieht bei solchen Verbindungen überwiegend Metadaten. Eine vollständige
Inhaltsprüfung würde zusätzliche Browser-, Endpunkt- oder verwaltete TLS-Integrationen sowie klare
Datenschutz- und Vertrauensregeln erfordern.

### Dienstbetrieb und Administration

Der LocalSystem-Core überwacht Broker, Gateway, Sensorzustand und Policyaktivierung. Begrenzter
Neustart-Backoff und ein Audit-only-Safe-Mode reduzieren die Gefahr unkontrollierter
Absturzschleifen. Eine erhöhte lokale Verwaltung unterstützt Health-Abfrage, Schlüsselrotation,
Quarantänefreigabe mit Begründung, Auditexport, Recovery und bestätigten Uninstall. Eine lokale
SOC-Konsole und SIEM-Ausgabeformate für JSON Lines, CEF und LEEF sind vorhanden.

Signierte A/B-Binärupdates mit Publisherprüfung und Rollback sind als technischer Pfad integriert.
Die Auslieferung über eine reale Unternehmens-PKI und einen freigegebenen Updatekanal ist davon zu
trennen und noch nicht als Produktprozess nachgewiesen.

## Berichtigung der vorgelegten Bewertung

| Ursprüngliche Aussage | Sachlich belastbare Einordnung |
|---|---|
| "unbezwingbare Desktop-Festung" | Kein Sicherheitssystem ist unbezwingbar. AI Shield reduziert konkrete Angriffsflächen und liefert zusätzliche Erkennung und Durchsetzung. |
| Timing-Angriffe seien mathematisch unmöglich | Der zeitkonstante HMAC-Vergleich reduziert eine konkrete Vergleichsseitenkanal-Klasse. Er schließt nicht alle Timing-, Cache-, Kernel- oder Hardwareseitenkanäle aus. |
| Die Quarantäne löse TOCTOU vollständig | Die handle-basierte Implementierung schließt wichtige Pfad- und Austauschrennen im definierten Aufnahmebereich. Sie ist keine universelle Garantie für alle Dateisysteme und Dateipfade. |
| Die Kausalitätskette sei nicht abstreitbar | Die lokale AISHAD02-Hashkette ist prüfbar und manipulationsanzeigend. Starke Unbestreitbarkeit verlangt einen externen Vertrauensanker und getrennte Aufbewahrung. |
| DPAPI-KeyVault und Recovery seien absolut absturzsicher | Write-through, primärer Slot, Recovery-Slot und Migration erhöhen die Robustheit. Stromverlust, Datenträgerdefekte, privilegierte Manipulation und Betriebsfehler bleiben mögliche Ausfälle. |
| Ein Parserkompromiss sei vollständig eingeschlossen | AppContainer, Job Object, privater Kanal und Deadline begrenzen Folgen erheblich. Die Vollständigkeit muss noch durch adversariale und langfristige Prüfungen belegt werden. |
| Native SIEM- und PowerShell-Weiterleitung seien produktiv aktiv | Formate, lokale Protokollierung und Forwarderpfade existieren. Reale Ziel-URLs, Zertifikatpins und WEF-Collector sind in der dokumentierten Umgebung nicht konfiguriert. |
| Das System sei sofort Enterprise-ready | Testsigning, deaktivierter Secure Boot und fehlende HLK/WHCP-, Feld- und unabhängige Sicherheitsnachweise verhindern diese Einstufung. |
| Gesamtwertung 9,4/10 | Diese Wertung bewertet Funktionsumfang, aber nicht ausreichend Nachweis- und Betriebsreife. Unter Einbeziehung der offenen Produktnachweise sind 6,8/10 angemessener. |

## Aktueller Windows-Sicherheitsstand

Der zuletzt dokumentierte Posture-Wert beträgt **16 von 28**. Vier Befunde sind kritisch:

1. Secure Boot ist für die lokale Testsigning-Umgebung deaktiviert.
2. Windows TESTSIGNING ist aktiviert.
3. Die Windows-Firewall ist in allen Profilen deaktiviert.
4. UAC fordert für Administratoren keine Zustimmung an.

Zusätzlich gelten folgende Einschränkungen:

- Credential Guard ist ohne UEFI-Lock vorbereitet, benötigt aber Neustart und Verifikation.
- Defender Cloud Reporting ist konfiguriert; Tamper Protection bleibt über Windows Security, Intune
  oder Configuration Manager zu verwalten.
- BitLocker ist nicht aktiv und wartet auf einen belastbaren externen Recovery-Prozess.
- WDAC und zwölf ASR-Regeln laufen im Auditmodus. Für ASR-Blockierung reicht die bisherige Evidenz
  von zwei Ereignissen gegenüber dem konfigurierten Schwellenwert von zwanzig nicht aus.
- Lokales PowerShell-ScriptBlock- und Modul-Logging ist aktiv. Der datensparsame externe Forwarder
  benötigt noch Zieladresse und Zertifikatpin.
- Browser-Native-Messaging-Host und lokal ladbare Erweiterung sind in Private Desktop integriert.
  Ohne Store- oder HTTPS-Updatequelle bleibt je Browser eine einmalige manuelle Ordnerbestätigung;
  ein verwalteter Enterprise-Rollout benötigt weiterhin reale Extension-ID und Update-URL.
- WEF benötigt einen realen Collector und eine gepinnte Zielidentität.

Eine produktive Pilotumgebung darf diese Punkte nicht durch pauschale Skriptänderungen erzwingen.
Firewall, UAC, BitLocker, Credential Guard, WDAC und ASR müssen mit vorhandenen VPN-, Entwicklungs-
und Verwaltungswegen abgestimmt und mit einem geprüften Rollback ausgerollt werden.

## Bedrohungen und Schutzwirkung

AI Shield kann die Wahrscheinlichkeit oder Wirkung folgender Angriffsmuster reduzieren:

- Netzwerkbasierte Würmer und laterale Bewegung über definierte riskante Ports;
- auffällige oder fehlerhafte IPv4-/IPv6-, ICMPv6- und QUIC-Metadaten;
- riskante Downloads mit Internet-Provenance über getrennte Dokument-, Archiv-, Bild-, Audio-,
  Video- und Webdatei-Policies sowie isolierte AMSI-/PDF-/ZIP-Prüfung;
- Prozessketten mit Office-Kindprozessen, Skriptinterpretern, LOLBins, Credential-Access- oder
  Persistenzmerkmalen;
- Manipulation oder Replay von Brokerereignissen und Policy-Rollback auf ältere Versionen;
- Parserfehler durch Prozessisolation, Ressourcenbudgets und Deadlines;
- lokale Spurenverwischung, sofern Auditdaten rechtzeitig extern weitergeleitet werden.

AI Shield gewährleistet keinen vollständigen Schutz vor:

- unbekannten Kernel-Zero-Days oder Fehlern in den eigenen Kernel-Treibern;
- Angreifern mit bereits erlangten Administrator-, SYSTEM-, Kernel- oder Firmware-Rechten;
- Schadcode innerhalb erlaubter, verschlüsselter Verbindungen ohne zusätzliche Inhaltssicht;
- kompromittierter Firmware, Hardware, Lieferkette oder Unternehmens-PKI;
- allen Dateiformaten, Protokollen, Fehlkonfigurationen und unbekannten Angriffstechniken;
- Bedienfehlern oder bewusst zu weit gefassten Allowlisten.

## Fehlende Produktnachweise

Vor einem breiten Produktivbetrieb sind mindestens folgende Nachweise erforderlich:

1. Microsoft-Treibersignierung und erfolgreicher Betrieb mit aktiviertem Secure Boot.
2. HLK/WHCP sowie HVCI- und Driver-Verifier-Prüfungen auf einer definierten Hardwarematrix.
3. Mehrtägige Last-, Missbrauchs-, Neustart-, Upgrade-, Recovery- und Deinstallationsläufe.
4. Messung von Fehlalarmen und Schutzwirkung mit repräsentativen Unternehmens- und Angriffskorpora.
5. Browser-, VPN-, EDR-, Backup-, Entwicklerwerkzeug- und Windows-Versionskompatibilität.
6. Externe WEF-/SIEM-Verankerung, Unternehmens-PKI und geprüfter Update-/Rollbackbetrieb.
7. Unabhängiges Threat Modeling, Quellcodeaudit, Penetrationstest und Red-Team-Prüfung.
8. Datenschutz-, Aufbewahrungs-, Rollen-, Support- und Incident-Response-Freigaben.

Die ausführliche Liste wird in
[`FEHLENDE_FUNKTIONEN_DE.md`](FEHLENDE_FUNKTIONEN_DE.md) gepflegt.

## Einsatzempfehlung

**Geeignet ist der aktuelle Stand für:**

- Entwicklung und Sicherheitsforschung;
- isolierte Labor- und Demonstrationsumgebungen;
- kontrollierte Pilotierung auf wenigen wiederherstellbaren Systemen nach dokumentierter
  Risikoakzeptanz;
- Erhebung der noch fehlenden Kompatibilitäts-, Fehlalarm- und Betriebsdaten.

**Nicht geeignet ist der aktuelle Stand für:**

- unbegleiteten Rollout auf produktive Standardarbeitsplätze;
- Systeme, die Secure Boot oder formell freigegebene Treiber voraussetzen;
- hochkritische Umgebungen ohne unabhängige Prüfung, externes Audit und belastbaren Recoveryplan;
- die Zusage eines vollständigen Schutzes vor modernen, KI-gestützten oder unbekannten Angriffen.

## Schlussfolgerung

AI Shield 2.0 besitzt mehr Substanz als ein reiner Demonstrator: Die Treiber, der Broker, die
ABI-2.0-Korrelation, Quarantäne, AppContainer-Isolation, Policyabsicherung und Windows-Adapter bilden
eine kohärente technische Plattform. Besonders positiv sind die expliziten Identitäten über mehrere
Sensorpfade, die handle-basierte Quarantäne und die Trennung von Beobachtung, Entscheidung und
Durchsetzung.

Die frühere Bewertung überschätzt jedoch die Gewissheit der Schutzwirkung. Begriffe wie
"unbezwingbar", "mathematisch unmöglich", "absolut absturzsicher" und "Enterprise-ready" sind durch
den vorhandenen Nachweisstand nicht gedeckt. Die korrekte Einordnung lautet deshalb:

> **Ein fortgeschrittener, funktionsreicher Windows-Sicherheitsprototyp mit überzeugender
> Architektur und mehreren realen Schutzpfaden, dessen Produktreife erst durch externe Signierung,
> Systemhärtung, Feldmessung und unabhängige Sicherheitsqualifikation belegt werden muss.**
