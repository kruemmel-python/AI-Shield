# Softwarebewertung: AI Shield Private Desktop

## Bewertungsrahmen

Bewertet wird ausschließlich der Einsatz auf einem privaten Windows-Einzelplatzrechner. Zentrale
Administration, Flottenbetrieb, externe Ereignissammler und Security-Operations-Prozesse gehören
nicht zum Umfang dieser Edition und fließen weder positiv noch negativ in die Wertung ein.

Die Bewertung basiert auf Quellcode, lokalen Build- und Testergebnissen sowie dem dokumentierten
Installationsstand vom 14. Juli 2026 einschließlich Content-Policy v3 und Download-
Freigabeschranke. Sie ist kein unabhängiger Penetrationstest und keine
Produktzertifizierung.

Der RC-1-Lauf bestätigt inzwischen reproduzierbare User-Mode- und Treiberbuilds, drei erfolgreiche
Debug-/Release-Testserien, fehlerfreie Inf2Cat-Pakete sowie einen lokalen Dual-Stack-Lastlauf. Diese
Nachweise verbessern die technische Evidenz, ersetzen aber nicht die weiterhin offenen erhöhten,
rebootpflichtigen, interaktiven und unabhängigen Prüfungen.

## Kurzurteil

AI Shield Private Desktop ist ein weit entwickelter Sicherheitsprototyp für technisch versierte
Privatnutzer. Er besitzt reale Windows-Kerneltreiber für Netzwerk-, Datei- und Prozessereignisse,
eine authentisierte Ereignispipeline, lokale Policy-Durchsetzung, gehärtete Quarantäne und
überwachte Systemdienste. Der normale Einzelplatzstart benötigt weder Webserver noch Backend-Port.

Die Edition ist trotzdem noch kein allgemein freigegebenes Endanwenderprodukt. Der entscheidende
Grund ist die lokale Testsignierung der Treiber: Secure Boot muss derzeit deaktiviert sein und
Windows läuft im TESTSIGNING-Modus. Damit ist der Prototyp für ein kontrolliertes Testsystem
geeignet, nicht für eine bedenkenlose Installation auf dem einzigen privaten Alltags-PC.

**Gesamtbewertung: 7,2 von 10 - technisch starker Einzelplatzprototyp mit noch fehlender sicherer
Treiberfreigabe und Felderprobung.**

## Teilbewertungen

| Bereich | Wertung | Einordnung |
|---|---:|---|
| Lokale Schutzarchitektur | 8,2/10 | Zusammenhängender Netzwerk-, Datei-, Prozess-, Policy- und Auditpfad |
| Bedienbarkeit | 7,4/10 | Eigene Ein-Klick-Skripte für Installation, Start, Status, Stopp und Deinstallation |
| Datei- und Prozessschutz | 7,5/10 | Starke handle-basierte Quarantäne und konkrete Prozessregeln mit begrenzter Abdeckung |
| Netzwerkmetadaten und Wurmschutz | 6,8/10 | IPv4/IPv6 und ausgewählte Wurmports; keine allgemeine Entschlüsselung von HTTPS/QUIC |
| Lokaler Datenschutz | 7,8/10 | Lokale Verarbeitung und kein erforderlicher externer Ereignisexport |
| Alltagskompatibilität | 6,0/10 | Konservative Vorgaben, aber noch keine breite Messung mit Spielen, VPNs und Privatsoftware |
| Installationssicherheit | 4,5/10 | Rollback vorhanden; Testsigning und deaktivierter Secure Boot verhindern Produktfreigabe |

## Was die Privatversion schützt

- Sie beobachtet IPv4- und IPv6-Flows und kann ausgewählte typische Wurm- und
  Lateral-Movement-Verbindungen blockieren.
- Sie erkennt Internet-Provenance bei ausgewählten neuen ausführbaren Dateien in Downloads und Temp
  und kann verdächtige Dateien handle-basiert quarantänisieren.
- Sie blockiert ausgewählte riskante Starts aus Quarantäne und Benutzer-Temp sowie auffällige
  Skript-, Office- und Systemwerkzeug-Prozessketten.
- Sie authentisiert Kernelereignisse, lehnt Replay und veraltete Policyversionen ab und führt eine
  lokal prüfbare Audit-Hashkette.
- Sie überwacht Broker und Core, begrenzt Neustartschleifen und kann in einen Audit-only-Safe-Mode
  wechseln.
- Sie ergänzt Windows-Firewall und Microsoft Defender durch eine rückrollbare lokale Auditbaseline.

## Sachliche Grenzen

Die Quarantäne verarbeitet nicht jede Datei auf jedem Datenträger. Sie konzentriert sich auf neue
Dateien mit Internet-Markierung, ausgewählte riskante Erweiterungen und definierte lokale Ordner.
Die WFP-Schicht sieht bei HTTPS und QUIC überwiegend Verbindungsmetadaten, nicht den verschlüsselten
Inhalt. ProcessGuard verwendet konkrete Regeln und ist keine vollständige Verhaltensanalyse jeder
denkbaren Prozesskette.

Kein lokales Schutzprogramm garantiert Sicherheit gegen unbekannte Kernel-Lücken, einen bereits als
Administrator oder SYSTEM aktiven Angreifer, kompromittierte Firmware oder manipulierte Hardware.
AI Shield muss deshalb zusammen mit Windows Update, Defender, aktiver Firewall, UAC,
Datenträgerverschlüsselung und getrennten Backups eingesetzt werden.

## Noch erforderliche Freigaben

1. Microsoft-signierte Treiber und verifizierter Betrieb mit Secure Boot ohne TESTSIGNING.
2. HVCI-, Driver-Verifier-, Neustart-, Update-, Recovery- und mehrtägige Lastprüfungen.
3. Kompatibilitätstests mit verbreiteten Browsern, Spielen, VPNs, Druckern und Privatsoftware.
4. Repräsentative Fehlalarmmessungen für Downloads, Installer, Skripte und Heimnetzverkehr.
5. Unabhängige Überprüfung des Kernelcodes, Penetrationstest und dokumentierter Recoverytest.
6. Endanwendergerechter signierter Installer mit Publisheridentität und sauberem Updatekanal.

## Einsatzempfehlung

Der aktuelle Stand eignet sich für einen wiederherstellbaren Test-PC oder eine kontrollierte
Pilotinstallation durch technisch erfahrene Privatnutzer. Für den einzigen produktiven Familien-
oder Arbeits-PC sollte die Edition erst nach Microsoft-Treibersignierung, aktiviertem Secure Boot
und erfolgreicher Kompatibilitätsprüfung verwendet werden.

Die korrekte Einordnung ist daher nicht "unbezwingbarer Schutz", sondern:

> Ein funktionsreicher lokaler Windows-Sicherheitsprototyp, der konkrete Netzwerk-, Download- und
> Prozessangriffe erschwert und sichtbar macht, ohne vollständigen Schutz versprechen zu können.
