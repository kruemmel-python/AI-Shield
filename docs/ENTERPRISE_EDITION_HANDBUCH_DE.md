# AI Shield Enterprise-Betriebsprofil

Stand: 14. Juli 2026

## Einordnung

Das Enterprise-Betriebsprofil verwendet denselben Sicherheitskern und dieselben Treiber wie Private
Desktop. Es ergänzt verwaltete Konfiguration, externe Auditverankerung und Rolloutkontrollen. Es ist
kein vollständig freigegebenes Unternehmensprodukt: Microsoft-Treibersignierung, HLK/WHCP,
Hardwarematrix, Langzeitmessung und unabhängige Prüfung bleiben Produktgates.

## Zusätzliche Integrationen

- verwalteter Edge-/Chrome-Sensor mit realer Extension-ID, HTTPS-Updatequelle und Publisherpin;
- Windows Event Forwarding zu einem Collector mit gepinnter Zielidentität;
- JSON-, CEF- und LEEF-SIEM-Ausgabe sowie IPv4-/IPv6-Syslog;
- PowerShell-Ereignismetadaten ohne Scripttext, mit TLS-Zertifikatpin;
- WDAC-Baseline im Auditmodus und Auswertung von Code-Integrity-Ereignis 3076;
- transaktionale Firewall-Baseline mit AI-Shield-, VPN- und Entwicklungsallowlists;
- evidenzbasierte ASR-Auswertung vor einer regelweisen Umstellung von Audit auf Block;
- lokale administrative/SOC-Schnittstelle für Health, Auditexport und begründete Quarantänefreigabe.

## Deployment-Vertrag

Vor einem Rollout muss die Organisation Collector-URLs, Zertifikatpins, Extension-ID,
Publisheridentität, Servicekonten, Aufbewahrungsfristen und Notfallzugänge bereitstellen. Leere oder
beispielhafte Werte dürfen nicht als produktive Konfiguration interpretiert werden. Die konkrete
Einrichtung ist in [Enterprise-Sicherheitsintegrationen](ENTERPRISE_SECURITY_INTEGRATIONS_DE.md)
und [Junior-Schnellstart](JUNIOR_ENTERPRISE_INTEGRATION_SCHNELLSTART_DE.md) beschrieben.

## Empfohlener Rollout

1. Reproduzierbaren Build und Paketmanifest prüfen.
2. Treiber mit Microsoft-Produktionssignatur auf der freigegebenen Windows-/Hardwarematrix testen.
3. WDAC, Defender, ASR und Firewall zunächst im Auditmodus beziehungsweise mit Pilotallowlists ausrollen.
4. WEF/SIEM und Recoveryzugang vor Enforcement verifizieren.
5. Fehlalarme mit Browsern, VPNs, Installern, Spielen, Entwicklungs- und Administrationswerkzeugen messen.
6. Regeln nur einzeln und mit dokumentiertem Rollback in den Blockiermodus übernehmen.
7. Unabhängiges Kernelreview und Penetrationstest vor breitem Rollout abschließen.

## Betriebsgrenzen

Ein lokaler Administrator oder SYSTEM-Angreifer kann lokale Telemetrie und Dienste angreifen;
deshalb ist eine manipulationsferne externe Auditkopie erforderlich. AI Shield ersetzt weder EDR,
Identitätsschutz, Patchmanagement, Firmwarevertrauen, Backup noch Incident Response.

