# Downloadschutz und Freigabeschranke

Stand: 15. Juli 2026, Content-Policy `AIShieldContentPolicy/4`

## Ziel

AI Shield behandelt einen erfolgreichen Download nicht automatisch als vertrauenswürdig. Neue
Dateien im Downloadordner werden nach Abschluss des Schreibvorgangs anhand einer
DPAPI-Machine-geschützten Dateityp-Policy geprüft. Mark-of-the-Web bleibt ein zusätzliches
Provenienzsignal, ist aber seit der WAV-Härtung keine Voraussetzung mehr: Auch Browser-Downloads
über „Speichern unter“, bei denen Windows keinen `Zone.Identifier` anlegt, werden erfasst. Bei
aktiver Freigabeschranke werden auch saubere
Dateien zunächst aus `Downloads` in die geschützte Quarantäne verschoben. Erst eine bewusste,
begründete Freigabe stellt sie wieder bereit.

Damit wird insbesondere die Lücke geschlossen, bei der ein Benutzer eine MP3-, WAV-, Bild-, PDF-
oder Skriptdatei unmittelbar nach dem Download öffnet, obwohl der Dateityp Parser- oder
Ausführungsrisiken besitzt.

## Dateigruppen

Die Desktop-UI bietet getrennte Schalter für:

1. Dokumente, einschließlich PDF, Office, OpenDocument, RTF und OneNote.
2. Archive und Datenträgerabbilder.
3. Bilder, Audio, Video und Webdateien.
4. Programme und Installer, etwa EXE, DLL, MSI, MSIX, APPX, CPL und SCR.
5. Windows-Skripte, etwa BAT, CMD, PS1, PSM1, VBS, JS, WSF und HTA.
6. Entwickler- und Shell-Skripte, etwa SH, Python, Node, Perl, Ruby, PHP und JAR.
7. Verknüpfungen und Systemaktionen, etwa LNK, URL, REG, INF, CHM und ClickOnce.
8. Unbekannte und Spezialformate, einschließlich Dateien ohne bekannte Endung, Modellgewichte,
   Firmware, CAD/GIS, Plugins, Mods und proprietäre Container.

Ein deaktivierter Gruppenschalter bedeutet ausdrücklich, dass AI Shield für diese Gruppe weder die
Inhaltsprüfung noch die Freigabeschranke durchsetzt. Der zusätzliche ProcessGuard-Schutz kann
direkte oder interpretergestützte Ausführung aus `Downloads` unabhängig davon weiterhin sperren.

## Entscheidungsablauf

```text
Browserdownload
      │
      ├─► neue/geänderte Datei und stabile Größe prüfen
      ├─► Mark-of-the-Web auswerten, falls vorhanden
      ├─► Reparse Point, Hardlink, ADS und Dateiidentität prüfen
      ├─► universeller Magic-/Polyglot-/Fähigkeiten-Preflight
      ├─► isolierter Minimalworker: AMSI sowie PDF-/ZIP-/RIFF-WAV-Strukturprüfung
      │
      ├─► Schadsoftware/Strukturrisiko ─► Quarantäne: Sicherheitsbefund
      └─► sauber + Freigabeschranke ────► Quarantäne: wartet auf Freigabe
                                              │
                                              └─► UI-Freigabe mit Ziel und Begründung
```

Der primäre Entscheidungspfad ist seit RC12 identitätsgebunden. Der Minifilter markiert die
Volume-/File-ID bei externen Schreibvorgängen als `pending` und sendet nach Cleanup eine
authentisierte Filter-Manager-Anfrage an den registrierten Broker. Dessen Empfangsthread bestätigt
die Aufnahme in die begrenzte Analysewarteschlange innerhalb von 250 ms. Bis der getrennte Worker
das endgültige Urteil per Broker-IOCTL setzt, sind Lesen, Vorschau, Mapping und Ausführung gesperrt.
Portausfall, Timeout, Warteschlangenüberlauf, Identitätswechsel oder Scannerfehler lassen nur das
betroffene Dateiobjekt gesperrt. Der sekündliche Verzeichnisscan bleibt als serialisierter
Recovery-Pfad bestehen. Die UI prüft alle zwei Sekunden auf neue Quarantäneobjekte und zeigt ein
Warnfenster.

Der Edge-/Chrome-Sensor liefert Navigations- und Downloadmetadaten. Er ist nicht der lokale
Byte-Scanner und erzeugt deshalb nicht zwingend die integrierte Browsermeldung „gefährlicher
Download“. Inhaltsentscheidung, Quarantäne und UI-Warnung erfolgen durch Broker und Scanner nach
dem Speichern. Vorhandene Dateien werden beim Brokerstart baseliniert; neue Dateien und spätere
Änderungen an bekannten Pfaden werden anhand von Größe und Änderungszeit erneut geprüft.

Der WAV-Preflight validiert RIFF-Größe, Chunk-Grenzen, `fmt `- und `data`-Chunk. Befehlsähnliche
Launcher-Tokens in Metadaten-Chunks werden als Strukturrisiko behandelt. Text in Metadaten wird
nicht ausgeführt; dieses Signal schützt gegen missbräuchliche Container und dient zusammen mit
Containerfehlern und AMSI/Defender der Klassifizierung.

Der ZIP-Preflight validiert lokale Header gegen das Central Directory, Data Descriptor, ZIP64,
UTF-8-Namen und CRC-32. Stored und raw DEFLATE werden rekursiv analysiert. Tiefe, Eintragszahl,
Einzel- und Gesamtgröße sowie Kompressionsverhältnis besitzen gemeinsame Budgets. Pfadflucht,
ADS-Namen, doppelte kanonische Pfade, überlappende Strukturen, ungültige Huffman-Tabellen,
Verschlüsselung und nicht unterstützte Methoden werden nicht automatisch freigegeben.

## Quarantäne und Freigabe

Die Quarantäneansicht unterscheidet mindestens:

- `Wartet auf Freigabe`
- `Schadsoftware erkannt`
- `Verdächtige Dateistruktur`
- `Prüfung nicht möglich`
- `Nicht vertrauenswürdige Ausführung`

Eine Freigabe benötigt einen Zielpfad und eine Begründung. Der Broker validiert Objekt-ID,
Dateiidentität und Zielzustand und protokolliert die Freigabe. Seit RC13 ruft die UI den Broker
direkt auf; dadurch enthält die ProcessGuard-überwachte PowerShell-Kommandozeile keinen Downloadpfad
mehr. Der Broker verlangt vor dem Verschieben genau einen Hardlink, prüft nach dem write-through
Move dieselbe Volume-/File-ID, protokolliert den Commit dauerhaft und hebt danach über einen nur
für Administratoren und `SYSTEM` zugänglichen Minifilter-IOCTL das Pending-/Quarantäneurteil für
genau dieses Objekt auf. Bei einem Fehler wird die Datei zurückverschoben und als `rolled_back`
protokolliert. Zielpfade auf einem anderen Volume werden derzeit absichtlich abgelehnt, weil dort
keine identische File-ID erhalten werden kann. Sicherheitsbefunde sollten nur nach fachlicher
Analyse freigegeben werden.

## Migration

Policy-v1- bis Policy-v3-Daten werden beim Lesen auf Policy v4 migriert. Neue Ausführungsgruppen,
die Gruppe für unbekannte Formate und `release_required=true` werden sicher voreingestellt. Die persistente Datei bleibt mit Windows
DPAPI im Maschinenkontext geschützt.

Status prüfen:

```powershell
.\build_vs\Release\ai_shield_broker.exe content-policy-status
```

Aktueller Standard:

```json
{"schema":"AIShieldContentPolicy/4","enabled_categories":2047,"fail_closed":true,"release_required":true}
```

## Qualifikation

Der automatisierte Test `tests/windows_download_content_protection.ps1` erzeugt ein sauberes Bild,
eine aktive PDF mit Mark-of-the-Web, eine absichtlich auffällige WAV ohne Mark-of-the-Web, ein PE
unter Bildendung, ein aktives SVG und eine unbekannte Endung. Er
weist nach, dass das Bild eine Benutzerfreigabe benötigt und PDF sowie WAV als Strukturfund
quarantänisiert werden. Ein zusätzlicher Unit-Test stellt sicher, dass eine korrekt aufgebaute
harmlose PCM-WAV keinen strukturellen Alarm auslöst. Der Test bereinigt seine Quarantäneobjekte
anschließend über den kontrollierten Restore-Pfad.

Der Scanner wird über dasselbe gesperrte Datei-Handle versorgt, das der Broker für Identitäts- und
Hashprüfung verwendet. Er erhält keinen Dateipfad zum erneuten Öffnen. Ein AppContainer ist der
primäre Startmodus. Falls der Windows-Loader eigene Binärdateien mit `0xC0000142` ablehnt, wird
explizit auf einen privilegienlosen Low-Integrity-Token im gleichen Einprozess-/Speicher-/Zeit-Job
zurückgefallen; ein LocalSystem-Parserfallback existiert nicht.

Der WFP-Treiber sperrt für `ai_shield_file_scanner.exe` zusätzlich sämtliche ein- und ausgehenden
IPv4-/IPv6-Verbindungen. Die Sperre gilt unabhängig vom normalen Policy-Modus und verhindert auch
im Low-Integrity-Fallback einen Netzwerkkanal aus dem Parserprozess.

