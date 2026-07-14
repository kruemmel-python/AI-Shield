# Downloadschutz und Freigabeschranke

Stand: 14. Juli 2026, Content-Policy `AIShieldContentPolicy/3`

## Ziel

AI Shield behandelt einen erfolgreichen Download nicht automatisch als vertrauenswürdig. Neue
Dateien mit Windows Mark-of-the-Web werden nach Abschluss des Schreibvorgangs anhand einer
DPAPI-Machine-geschützten Dateityp-Policy geprüft. Bei aktiver Freigabeschranke werden auch saubere
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

Ein deaktivierter Gruppenschalter bedeutet ausdrücklich, dass AI Shield für diese Gruppe weder die
Inhaltsprüfung noch die Freigabeschranke durchsetzt. Der zusätzliche ProcessGuard-Schutz kann
direkte oder interpretergestützte Ausführung aus `Downloads` unabhängig davon weiterhin sperren.

## Entscheidungsablauf

```text
Browserdownload
      │
      ├─► Mark-of-the-Web und stabile Dateigröße prüfen
      ├─► Reparse Point, Hardlink, ADS und Dateiidentität prüfen
      ├─► Defender/AMSI sowie PDF-/ZIP-Strukturprüfung
      │
      ├─► Schadsoftware/Strukturrisiko ─► Quarantäne: Sicherheitsbefund
      └─► sauber + Freigabeschranke ────► Quarantäne: wartet auf Freigabe
                                              │
                                              └─► UI-Freigabe mit Ziel und Begründung
```

Der Broker wiederholt die Downloadsuche im Ein-Sekunden-Takt und verlangt zwei identische
Größenbeobachtungen, damit eine noch geschriebene Datei nicht vorzeitig verarbeitet wird. Die UI
prüft alle zwei Sekunden auf neue Quarantäneobjekte und zeigt ein Warnfenster. Dieser asynchrone
Ablauf reduziert das Zeitfenster erheblich, ist aber kein synchroner Kernel-Dialog beim Öffnen.

## Quarantäne und Freigabe

Die Quarantäneansicht unterscheidet mindestens:

- `Wartet auf Freigabe`
- `Schadsoftware erkannt`
- `Verdächtige Dateistruktur`
- `Prüfung nicht möglich`
- `Nicht vertrauenswürdige Ausführung`

Eine Freigabe benötigt einen Zielpfad und eine Begründung. Der Broker validiert Objekt-ID,
Dateiidentität und Zielzustand und protokolliert die Freigabe. Sicherheitsbefunde sollten nur nach
fachlicher Analyse freigegeben werden.

## Migration

Policy-v1- und Policy-v2-Daten werden beim Lesen auf Policy v3 migriert. Neue Ausführungsgruppen und
`release_required=true` werden sicher voreingestellt. Die persistente Datei bleibt mit Windows
DPAPI im Maschinenkontext geschützt.

Status prüfen:

```powershell
.\build_vs\Release\ai_shield_broker.exe content-policy-status
```

Erwarteter RC9-Standard:

```json
{"schema":"AIShieldContentPolicy/3","enabled_categories":1023,"fail_closed":true,"release_required":true}
```

## Qualifikation

Der automatisierte Test `tests/windows_download_content_protection.ps1` erzeugt ein sauberes Bild
und eine aktive PDF mit Mark-of-the-Web. Er weist nach, dass das Bild eine Benutzerfreigabe benötigt,
die aktive PDF als Strukturfund quarantänisiert und beide Entscheidungen in der Provenienz erfasst
werden. Der Test bereinigt seine Quarantäneobjekte anschließend über den kontrollierten
Restore-Pfad.

