# AI Shield RC9 Release- und Installationsnachweis

Stand: 14. Juli 2026, Release Candidate `2.0.0-rc.9`

## Umfang

RC9 erweitert den verifizierten RC8-Stand um Content-Policy v3 und eine standardmäßig aktive
Download-Freigabeschranke. Programme, Skripte, Systemlauncher, Dokumente, Archive, Bilder, Audio,
Video und Webdateien können getrennt gesteuert werden. Saubere Downloads aktiver Gruppen werden
nach der Prüfung bis zur begründeten Benutzerfreigabe quarantänisiert.

Weitere RC9-Änderungen:

- ProcessGuard erkennt zusätzliche Sprachinterpreter und Windows-Systemlauncher.
- Die Desktop-UI besitzt 59 vertraglich geprüfte Controls.
- Neue Quarantäneobjekte erzeugen eine sichtbare UI-Warnung.
- Die Quarantäneansicht zeigt einen lokalisierten Entscheidungsgrund.
- Policy-v1-/v2-Daten migrieren sicher auf Policy v3.
- Der Scanzyklus wurde auf eine Sekunde verkürzt; stabile Dateigröße bleibt Voraussetzung.
- Der Download-Integrationstest verlangt nun auch für eine saubere Bilddatei eine Freigabe.

## Verifizierte lokale Prüfungen

| Prüfung | Ergebnis |
|---|---|
| CMake Release-Build | bestanden |
| Release-CTest | 12 von 12 bestanden |
| Debug-Build und Debug-CTest | 12 von 12 bestanden |
| Broker-Selbsttest | bestanden |
| UI-Vertrag | 59 Controls, 6 Ansichten |
| Release-Freeze | gültig für `2.0.0-rc.9` |
| ProcessGuard `.ps1`-/`.bat`-Laufzeittest | bestanden |
| Realer Downloadtest | sauberes Bild freigabepflichtig, aktive PDF quarantänisiert |

Der reale Downloadtest wurde auf dem Referenzrechner gegen den installierten LocalSystem-Broker
ausgeführt. Beobachtete Kernausgabe:

```text
safe_image_requires_release=true
active_pdf_quarantined=true
provenance_recorded=true
download_content_protection=installed
```

## Release-Artefakte

Der GitHub-Release `v2.0.0-rc.9` enthält:

- `AI_Shield_Private_Desktop.zip`
- `AI_Shield_Private_Desktop_2.0.0-rc.9_x64.msi`
- `AI_Shield_Developer_ABI2.zip`
- `AI_Shield_Developer_Full.zip`
- `SHA256SUMS.txt`

Die konkreten SHA-256-Werte stehen in `SHA256SUMS.txt` des Releases. ZIP-Pakete enthalten zusätzlich
eigene Dateimanifeste.

## Signierungs- und Freigabegrenze

MSI und Treiber sind mit dem lokalen AI-Shield-Testzertifikat signiert. Das ist kein öffentliches
Microsoft-Vertrauen. Die Installation der Kernelmodule auf dem Entwicklungsstand erfordert
deaktivierten Secure Boot und aktiviertes Windows-Testsigning. Vor einer öffentlichen
Produktionsfreigabe bleiben Microsoft-Treibersignierung, HLK/WHCP, HVCI-/Driver-Verifier-Läufe,
Kompatibilitätsmessungen und ein unabhängiger Security Review erforderlich.

