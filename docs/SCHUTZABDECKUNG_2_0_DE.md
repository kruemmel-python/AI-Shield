# AI Shield Schutzabdeckung 2.0

Stand: 14. Juli 2026

## Browser- und Download-Inhaltsprüfung

Der Edge-/Chrome-Sensor liefert datensparsame Navigations- und Downloadmetadaten über einen
signierten Native-Messaging-Host. Neu angelegte Mark-of-the-Web-Dateien werden abhängig von einer
DPAPI-Machine-geschützten Dateityp-Policy an eine feste Dateiidentität gebunden und in einem
zeitbegrenzten isolierten Scanner geprüft. Defender/AMSI deckt bekannte Schadsoftware ab; PDF- und
ZIP-Preflight prüfen zusätzlich aktive, fehlerhafte, verschlüsselte und strukturell riskante
Inhalte. Nicht prüfbare risikoreiche Formate können fail-closed quarantänisiert werden. Content-
Policy v3 ergänzt eine standardmäßig aktive Freigabeschranke: Auch sauber geprüfte Downloads
aktiver Gruppen werden bis zur begründeten Benutzerfreigabe quarantänisiert und in der UI gemeldet.
RC11 erweitert diese Schranke mit Content-Policy v4 auf unbekannte und spezialisierte Formate,
Magic-/Extension-Abgleich, Polyglot-/Trailing-Data-Erkennung, einen Handle-gebundenen Minimalworker
und eine WFP-erzwungene Netzwerksperre des Scanners.
Details enthält [Downloadschutz und Freigabeschranke](DOWNLOADSCHUTZ_UND_FREIGABE_DE.md).

## Audit Viewer

Die Private-Desktop-UI validiert und dekodiert lokale sowie exportierte AISHAD02-Dateien. Sequenz,
Disposition, Grundmaske, Prozess-/Parent-, Flow-, Datei-, Volume-, Provenance-, Policy- und
Modellbezug sowie Evidenzhash bleiben sichtbar und filterbar. Das ursprüngliche Binärformat bleibt
der Integritätsnachweis; JSON ist eine lesbare Ableitung.

## ETW und AMSI

`etw_amsi_adapter` übersetzt ETW-Provider-/Eventmetadaten und AMSI-Scanergebnisse in HMAC-geschützte
ABI-2.0-Sensorereignisse. Alle Korrelations-, Policy- und Modellbezüge bleiben erhalten.
`scan_with_amsi` kapselt Initialisierung, Scan, Ergebnis und Inhaltshash mit festen Größenlimits.

## IPv6, ICMPv6 und QUIC

`ipv6_security` validiert IPv6-Nutzlastlänge und eine auf acht Elemente begrenzte Extension-Chain.
Unterstützt werden Hop-by-Hop, Routing, Fragment, Destination Options und Authentication Header.
Fragment-ID, Offset, More-Bit und atomare Fragmente werden erfasst. Bei ICMPv6 werden Typ und Code
extrahiert. Der QUIC-Parser validiert Long Header, Version, Pakettyp, Connection-IDs und Token-Varints.

## ProcessGuard

Zusätzlich zu Quarantäne-, Temp-, Download-, Script-/LOLBIN-, Office-Child- und Handle-Injection-
Regeln erkennt ProcessGuard typische Credential- und Persistence-Kombinationen: LSASS-Dumps,
Registry-Hive-Export, geplante Tasks, Service- und Run-Key-Erstellung sowie WMIC-Prozessstart.
Observed-/Allowed-/Blocked-Zähler unterstützen die Fehlalarmqualifikation.

## AppContainer-Parserpool

`ParserPool` begrenzt aktive Worker, startet sie als AppContainer im Job Object und übergibt einen
lokalen Result-Pipe-Namen über `AI_SHIELD_RESULT_PIPE`. Die Pipe weist Remoteclients ab, besitzt eine
SYSTEM-/Owner-ACL und ist auf eine Instanz und 64 KiB begrenzt. Der Deadline-Wächter beendet
überfällige Worker; das Job Object begrenzt Speicher und Prozessanzahl.

## TPM-Trust-Anchor

Der optionale Trust Anchor verwendet den Microsoft Platform Crypto Provider. Er erzeugt einen
maschinenweiten, nicht exportierbaren RSA-Schlüssel und signiert SHA-256-Challenges:

```powershell
build_vs\Release\ai_shield_integrations.exe tpm-status
build_vs\Release\ai_shield_integrations.exe tpm-provision
```

DPAPI bleibt der Recovery-fähige Runtime-Schutz; TPM ist eine zusätzliche Hardwarebindung.

## SIEM

Der Shared Core erzeugt JSON Lines, CEF und LEEF mit Korrelations-, Policy- und Modellbezug. Der
Windows-Connector unterstützt IPv4/IPv6-Syslog über UDP oder TCP mit Größenlimit:

```powershell
build_vs\Release\ai_shield_integrations.exe siem-test 127.0.0.1 6514 cef
```

## SOC-Konsole

Die lokale Konsole läuft ausschließlich auf `127.0.0.1`, verlangt einen erhöhten Start, weist
Remoteclients ab und schützt API-Aufrufe mit einem zufälligen CSRF-Token. Sie zeigt Health,
Runtimeversion und Dienste und unterstützt Safe-Mode-Reset sowie begründete Quarantänefreigabe.

```powershell
powershell -ExecutionPolicy Bypass -File platform\windows\soc_ui\start_soc_console.ps1
```

Danach: `http://127.0.0.1:18443/`.
