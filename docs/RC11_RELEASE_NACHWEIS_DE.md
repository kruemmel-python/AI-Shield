# AI Shield RC11 Release- und Installationsnachweis

Stand: 14. Juli 2026, Release Candidate `2.0.0-rc.11`

## Umfang

RC11 erweitert RC10 um eine universelle, TOCTOU-feste Datei-Preflight-Kette. Der Broker bindet
Dateiidentität, SHA-256, Klassifizierung, isolierte Analyse und Quarantäne an dasselbe geöffnete
Dateiobjekt. Unbekannte und nicht tief analysierbare Formate werden nicht mehr still freigegeben.

Neu sind insbesondere:

- Content-Policy v4 mit elf Kategorien und der Bitmaske `2047`;
- Magic-/Extension-/Namensabgleich und Polyglot-/Trailing-Data-Erkennung;
- gehärtete WAV- und ZIP-Strukturprüfung;
- dedizierter Handle-Scanner mit AppContainer und kontrolliertem Low-Integrity-Fallback;
- WFP-erzwungene IPv4-/IPv6-Netzwerksperre des Scannerprozesses;
- erneute Prüfung veränderter Dateien und Downloadprüfung auch ohne MOTW;
- SHA-256-Provenienz und neue UI-Kategorie **Unbekannte und Spezialformate**.

Die vollständige Anforderungszuordnung steht im Abschnitt **Implementiert** von
`AI_Shield_Dateibasierte_Angriffe_und_Scananforderungen_DE.md`.

## Verifizierte lokale Prüfungen

| Prüfung | Ergebnis |
|---|---|
| Release-CTest | 15 von 15 bestanden |
| Debug-CTest | 15 von 15 bestanden |
| Download-Missbrauchstest | PDF, WAV, getarnte PE und SVG blockiert |
| Unbekannte Endung | Freigabeschranke bestätigt |
| Provenienz | SHA-256 im Datensatz bestätigt |
| Installierter Schutzstatus | WFP, Minifilter, ProcessGuard, Broker und Core aktiv |
| Content-Policy | `AIShieldContentPolicy/4`, `2047`, Fail-closed |
| Scannerisolation | Handle-only, Job-Limits und WFP-Netzwerksperre |

Die endgültigen äußeren Hashwerte stehen ausschließlich in `SHA256SUMS.txt`. Desktop- und
Developer-Full-Paket enthalten zusätzlich interne Dateimanifeste. Dadurch enthält kein Paket den
eigenen rekursiv instabilen Hash.

## Release-Artefakte

Der GitHub-Release `v2.0.0-rc.11` enthält:

- `AI_Shield_Private_Desktop.zip`
- `AI_Shield_Private_Desktop_2.0.0-rc.11_x64.msi`
- `AI_Shield_Developer_ABI2.zip`
- `AI_Shield_Developer_Full.zip`
- `SHA256SUMS.txt`

## Signierungs- und Freigabegrenze

MSI und Treiber sind weiterhin lokal testsigniert. Für eine öffentliche Installation bei aktivem
Secure Boot sind Microsoft-Produktionstreibersignierung, HLK/WHCP, rebootpflichtige HVCI-/Driver-
Verifier-Läufe, Langzeit- und Kompatibilitätsmessungen sowie ein unabhängiger Security Review nötig.
Die neue Datei-Schutzabdeckung ändert diese externe Freigabegrenze nicht.
