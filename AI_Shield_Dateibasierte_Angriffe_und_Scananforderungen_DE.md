# AI Shield – Bedrohungskatalog für dateibasierte Angriffe

## Implementierungsstand in AI Shield

Stand: 14. Juli 2026, `AIShieldContentPolicy/4`

Der Katalog ist zugleich Zielbild und Negativtestvertrag. Der produktive Downloadpfad behandelt
inzwischen jede nach Brokerstart neu angelegte oder geänderte Datei, einschließlich unbekannter
Endungen und Spezialformate. Nicht vollständig verstandene Inhalte werden nicht als sauber
behauptet: Bei aktiver Standardpolicy gelangen sie in die Freigabeschranke; Scanfehler,
Strukturanomalien, aktive Fähigkeiten und nicht prüfbare risikoreiche Container werden fail-closed
quarantänisiert.

Implementiert und im lokalen Systemtest nachgewiesen sind:

- vollständiger Streaming-SHA-256 sowie Volume-/File-ID-gebundene Quarantäneidentität,
- Prüfung unabhängig von Mark-of-the-Web und erneute Prüfung geänderter bekannter Pfade,
- Magic-/Extension-Abgleich, Tarnnamen, Polyglot- und Trailing-Data-Indikatoren,
- eingebettete PE-Signaturen, aktive Web-/Office-/Skriptfähigkeiten, automatische Aktionen,
  externe URI-/UNC-Indikatoren, unsichere Deserialisierungsformate und PE-Entropiesignale,
- strikte PDF-, ZIP- und RIFF/WAV-Vorprüfung; verschlüsselte, verschachtelte, ausführbare,
  duplizierte oder nicht tief extrahierbare ZIP-Kinder werden nicht automatisch freigegeben,
- dedizierter Minimalworker mit nur `Kernel32` als statischer Systemabhängigkeit, exakt einem
  vererbten Datei-Handle, Einprozess-Job, 512-MiB-Grenze, Deadline und ohne Netzwerkfreigabe,
- AppContainer als primärer Startmodus; auf dem aktuell qualifizierten Windows-Build führt dessen
  Loader bei eigenen Binärdateien zu `0xC0000142`, weshalb kontrolliert ein privilegienloser
  Low-Integrity-Token im identischen Job verwendet und der Degradationsgrund auditiert wird,
- WFP-erzwungene vollständige IPv4-/IPv6-Netzwerksperre für `ai_shield_file_scanner.exe`, die
  unabhängig vom normalen Policy-Modus auch den Low-Integrity-Fallback einschließt,
- Policy-v3-zu-v4-Migration und UI-Schalter **Unbekannte und Spezialformate**.

Nicht als vollständig implementiert gelten formatspezifische CDR-Rekonstruktion, Detonation in
jedem realen Zielprogramm, Cloud-/Publisher-Reputation, Passwortentschlüsselung, semantische
Steganografieerkennung, Modell-Backdoor-Evaluation sowie hersteller- und gerätespezifische
Firmware-, CAD-, CNC- oder Maschinenvalidierung. Diese Inhalte werden konservativ gesperrt oder
freigabepflichtig behandelt; das ersetzt keine vollständige semantische Validierung.

## Zweck

Dieses Dokument definiert die Angriffsflächen, Dateifamilien, Aktivierungsmechanismen und Prüfanforderungen, die AI Shield bei eingehenden, gespeicherten, geöffneten, dargestellten, entpackten, eingebundenen oder ausgeführten Dateien berücksichtigen muss.

Der Katalog ist absichtlich **format- und verhaltensorientiert**. Eine reine Liste von Dateiendungen ist unzureichend, weil Angreifer:

- Dateiendungen fälschen oder mehrfach verwenden,
- MIME-Typen manipulieren,
- mehrere gültige Formate in einer Polyglot-Datei kombinieren,
- ausführbare Inhalte in Container- und Dokumentformaten verschachteln,
- Parserfehler statt offiziell vorgesehener Skriptfunktionen ausnutzen,
- Inhalte verschlüsseln oder stark verschleiern,
- harmlose Dateien nur als Träger für Konfiguration, Schlüssel oder zweite Angriffsstufen verwenden,
- erst beim Vorschau-, Thumbnail-, Indexierungs-, Import-, Druck- oder Konvertierungsvorgang auslösen.

**Grundregel:** Nicht die Dateiendung entscheidet über das Risiko, sondern die Gesamtheit aus tatsächlichem Binärformat, Herkunft, enthaltenen Objekten, referenzierten Ressourcen, Parserpfad, Benutzeraktion und beobachtetem Laufzeitverhalten.

---

## 1. Wichtige Klarstellung zum WAV-Beispiel

Eine standardkonforme WAV-Datei besitzt keine allgemeine Betriebssystemfunktion, mit der sie selbstständig im Hintergrund eine Internetadresse aufrufen kann.

Ein Netzwerkzugriff im Zusammenhang mit einer WAV-Datei kann jedoch durch folgende Mechanismen entstehen:

1. **Verwundbarer Audio-Parser oder Codec**  
   Manipulierte RIFF-Blöcke, Längenfelder oder Codec-Daten lösen Speicherfehler im Player, Explorer-Preview-Handler, Indexer oder Konverter aus. Nach erfolgreicher Ausnutzung kann der kompromittierte Prozess Netzwerkzugriffe durchführen.

2. **Missbrauch von Metadaten**  
   URL-artige Werte, Cover-Art, ID3-kompatible Zusatzdaten oder anwendungsspezifische RIFF-Chunks werden von einer bestimmten Software als externe Ressource interpretiert.

3. **Playlist oder Begleitdatei**  
   M3U, PLS, ASX, CUE oder eine Projektdatei verweist auf eine lokale Audiodatei und gleichzeitig auf entfernte Ressourcen, UNC-Pfade oder Web-Adressen.

4. **Polyglot-Datei**  
   Dieselben Bytes werden von einem Programm als Audio und von einem anderen Parser als Archiv, Skript, HTML oder ausführbares Format interpretiert.

5. **Versteckte zweite Stufe**  
   Audio-Nutzdaten oder Metadaten enthalten verschlüsselte beziehungsweise steganografische Nutzdaten, die erst durch bereits vorhandene Schadsoftware extrahiert werden. Die WAV-Datei selbst führt dabei nichts aus.

6. **Dateinamen- oder Shell-Missbrauch**  
   Der Dateiname, ein Begleit-Link, ein Shortcut oder eine Shell-Erweiterung führt nicht den Audiostream, sondern einen anderen Befehl aus.

AI Shield muss deshalb nicht nach einem abstrakten „Link in WAV“ suchen, sondern nach **Parseranomalien, externen Referenzen, Polyglot-Merkmalen, eingebetteten Objekten, ungewöhnlichen Metadaten und anschließendem Prozess-/Netzwerkverhalten**.

---

# 2. Universelle Angriffsklassen

Diese Angriffsklassen gelten formatübergreifend.

## 2.1 Direkte Programmausführung

Die Datei ist selbst ausführbar oder wird von einem Interpreter ausgeführt.

**Beispiele für Trägerklassen:**

- native Programme und Bibliotheken,
- Kernel-Treiber,
- Installer,
- Skripte,
- Java-, .NET- oder WebAssembly-Module,
- IDE-, Build- und Paketmanagerdateien.

**Prüfungen:**

- tatsächliche Formatkennung statt Dateiendung,
- Signatur, Zertifikatskette, Zeitstempel und Widerrufsstatus,
- Importtabellen, Exporte, Entry Points und TLS Callbacks,
- ausführbare Speichersegmente,
- eingebettete Ressourcen und Overlay-Daten,
- verdächtige Interpreter- oder Systemwerkzeugaufrufe,
- Side-Loading- und Suchpfadrisiken,
- Herkunft, Reputation und MOTW,
- bekannte verwundbare signierte Treiber,
- erwartete Publisher- und Produktidentität.

## 2.2 Aktive Inhalte

Das Format enthält offiziell vorgesehene aktive Elemente.

**Beispiele:**

- VBA- und XLM-Makros,
- JavaScript in PDF oder HTML,
- ActiveX,
- OLE-Automation,
- Formularaktionen,
- DDE,
- eingebettete Skripte,
- PostScript,
- Datenbankmakros,
- Build- und Installationsaktionen.

**Prüfungen:**

- vollständige Extraktion aktiver Komponenten,
- automatische Start- und Open-Aktionen,
- Child-Process-Fähigkeit,
- Dateisystem-, Registry- und Netzwerkzugriffe,
- verschleierte Strings und dynamisch erzeugte Befehle,
- Missbrauch legitimer Systemprogramme,
- Signatur und Vertrauensstellung des aktiven Inhalts,
- blockierende Laufzeitregeln unabhängig vom statischen Urteil.

## 2.3 Externe Ressourcen und Remote-Referenzen

Eine Datei verweist auf Inhalte außerhalb der Datei.

**Mögliche Ziele:**

- HTTP/HTTPS,
- SMB/UNC,
- WebDAV,
- FTP und andere URI-Schemata,
- lokale oder entfernte Dateien,
- Vorlagen,
- Bilder,
- Stylesheets,
- Fonts,
- Datenquellen,
- Medien,
- Add-ins,
- Schemas,
- Pakete,
- Update- und Downloadendpunkte.

**Risiken:**

- Credential-Leak über automatische Authentifizierung,
- Tracking,
- Nachladen einer zweiten Stufe,
- Phishing,
- Umgehung der Anhangprüfung,
- Manipulation nach dem ursprünglichen Scan,
- interne Netzwerkabfragen und SSRF-artige Effekte.

**Prüfungen:**

- alle URI- und Pfadfelder normalisieren,
- IP-Literale, IDN/Punycode und Unicode-Homografen erkennen,
- UNC-, WebDAV- und lokale Pfade gesondert bewerten,
- automatische von klickabhängigen Referenzen unterscheiden,
- Redirect-Ketten und DNS-Auflösung kontrollieren,
- Zielreputation und Zertifikatsidentität prüfen,
- Remote-Inhalte standardmäßig nicht beim Preview laden.

## 2.4 Eingebettete Objekte und Container

Eine Datei enthält weitere Dateien oder Objektströme.

**Beispiele:**

- ZIP in Office-Dokumenten,
- OLE Package,
- PDF-Portfolios und Attachments,
- E-Mail-Anhänge,
- Matroska-Attachments,
- eingebettete Fonts, Bilder und Skripte,
- App- und Installationspakete,
- Disk-Images.

**Prüfungen:**

- rekursive Extraktion mit festen Budgets,
- jede Kinddatei erneut vollständig klassifizieren,
- Parent-Child-Provenienz erhalten,
- keine Vertrauensübernahme allein vom Container,
- verschlüsselte oder nicht extrahierbare Kinder als eigenes Risiko behandeln.

## 2.5 Parser- und Codec-Ausnutzung

Die Datei missbraucht einen Fehler in einem Parser, Decoder, Preview-Handler, Thumbnailer, Indexer, Drucker, Konverter oder Importfilter.

**Typische Fehlerklassen:**

- Integer Overflow und Underflow,
- Out-of-Bounds Read/Write,
- Use-after-free,
- Double Free,
- Type Confusion,
- Stack- oder Heap-Überlauf,
- Endlosschleifen,
- Rekursionsüberlauf,
- fehlerhafte Offsets und Längen,
- überlappende Datenbereiche,
- zyklische Objektgraphen,
- inkonsistente Tabellen und Indizes.

**Prüfungen:**

- strikte Strukturvalidierung vor tiefer Dekodierung,
- alle Additionen und Multiplikationen größenbegrenzt,
- Parser in isolierten, nicht privilegierten Prozessen,
- harte Zeit-, Speicher-, Objekt- und Ausgabelimits,
- Parserabsturz als Sicherheitsereignis werten,
- keine komplexe Dateidekodierung im Kernel durchführen.

## 2.6 Polyglot- und Formatverwechslungsangriffe

Eine Datei ist für mehrere Parser gültig oder täuscht ein anderes Format vor.

**Beispiele:**

- Bild plus Archiv,
- PDF plus ZIP,
- Skript mit gültigem Bildheader,
- PE-Datei mit harmloser Endung,
- HTML als Office- oder Textdatei,
- SVG als vermeintlich passives Bild.

**Prüfungen:**

- Magic Bytes, Dateiendung, MIME und Parserergebnis vergleichen,
- zusätzliche gültige Header an ungewöhnlichen Offsets suchen,
- Trailing Data und Overlay analysieren,
- alle plausiblen Parserpfade bewerten,
- widersprüchliche Klassifikation als hohes Risiko behandeln.

## 2.7 Verschleierung, Packing und Verschlüsselung

**Techniken:**

- komprimierte oder gepackte Programme,
- Base64/Hex/Unicode-Escapes,
- verschachtelte Skriptkodierung,
- dynamische Stringzusammensetzung,
- verschlüsselte Archive,
- passwortgeschützte Dokumente,
- verschlüsselte PDF-Objekte,
- stark entropische Blöcke,
- getrennte Schlüssel- und Nutzdatendateien.

**Prüfungen:**

- Entropie- und Packing-Indikatoren,
- sichere Dekodierung häufiger Kodierungen,
- Schichtenzahl begrenzen,
- verschlüsselte Inhalte nicht als sauber einstufen,
- nicht prüfbare aktive Inhalte blockieren oder isolieren,
- Passwortübergabe niemals automatisch aus Mailtext oder Dateiname übernehmen.

## 2.8 Ressourcenerschöpfung

**Beispiele:**

- ZIP-/Dekompressionsbomben,
- XML Entity Expansion,
- extrem große Bilddimensionen,
- sehr viele Frames, Seiten, Tabellen, Objekte oder Archiveinträge,
- künstlich lange Audiodauer bei kleiner Datei,
- zyklische Referenzen,
- verschachtelte Container,
- Sparse Files,
- Milliarden kleiner Dateien,
- Hashing- oder Parserkomplexitätsangriffe.

**Prüfungen:**

- komprimierte und erwartete entpackte Größe,
- Expansionsverhältnis,
- Rekursionstiefe,
- Objektanzahl,
- maximale Dimensionen, Dauer und Seitenzahl,
- CPU-, RAM-, Handle-, Thread- und Zeitbudget,
- Abbruch muss fail-closed oder mindestens isolation-required ergeben.

## 2.9 Pfad- und Dateisystemangriffe

**Techniken:**

- `..`-Traversal,
- absolute Pfade,
- UNC- und WebDAV-Pfade,
- symbolische Links und Hardlinks,
- Reparse Points,
- NTFS Alternate Data Streams,
- reservierte Windows-Gerätenamen,
- nachgestellte Punkte oder Leerzeichen,
- Groß-/Kleinschreibungs- und Unicode-Kollisionen,
- sehr lange Pfade,
- Überschreiben bestehender Dateien,
- DLL-Suchpfadpräparation.

**Prüfungen:**

- kanonische Pfadbildung vor jeder Policyentscheidung,
- Extraktion ausschließlich in neuem, nicht gemeinsam genutztem Verzeichnis,
- keine Linkverfolgung,
- keine absoluten oder außerhalb des Zielroots liegenden Ziele,
- stabile File-ID und Volume-ID kontrollieren,
- sichere Erstellung mit exklusiven Handles,
- ADS und Reparse Points explizit erfassen.

## 2.10 Metadatenmissbrauch

Metadaten sind nicht grundsätzlich passiv.

**Risiken:**

- externe URLs,
- sehr große oder rekursive Metadaten,
- Parserfehler,
- Shell- oder Kommandoinjektion in nachgelagerte Tools,
- versteckte Nutzdaten,
- Tracking-IDs,
- Täuschung von Benutzeroberflächen,
- manipulierte Zeitstempel und Autorenfelder.

**Prüfungen:**

- Metadaten wie untrusted input behandeln,
- Längen und Zeichensätze begrenzen,
- keine direkte Übergabe an Shell oder Kommandozeile,
- URLs, Pfade und Steuerzeichen extrahieren,
- eingebettete Vorschaubilder separat prüfen.

## 2.11 Vorschau-, Thumbnail- und Indexierungsangriffe

Eine Datei kann verarbeitet werden, ohne dass der Benutzer sie ausdrücklich öffnet.

**Trigger:**

- Windows Explorer Preview Pane,
- Thumbnail-Generator,
- Suchindex,
- Metadatenhandler,
- Medienbibliothek,
- E-Mail-Vorschau,
- Cloud-Synchronisationsclient,
- DLP- oder AV-Scanner,
- Druckvorschau.

**Prüfungen:**

- Download-/Create-Gate vor Shell- und Preview-Verarbeitung,
- MOTW und Herkunft beibehalten,
- Preview in isoliertem Prozess,
- keine externen Ressourcen in Vorschau,
- Parsercrash und unerwartete Netzwerkaktivität erfassen.

## 2.12 Social Engineering und UI-Täuschung

**Techniken:**

- doppelte Dateiendungen,
- versteckte bekannte Endungen,
- Right-to-Left Override,
- Icon-Spoofing,
- falsche Dokumenttitel,
- Linktext ungleich Ziel,
- gefälschte Sicherheitswarnungen,
- „Enable Content“-Köder,
- Dateien, die wie Ordner oder PDFs aussehen.

**Prüfungen:**

- tatsächlichen Typ sichtbar machen,
- Unicode-Steuerzeichen markieren,
- Icon und Dateityp nicht als Vertrauenssignal verwenden,
- sichtbare und tatsächliche Linkziele vergleichen,
- riskante Endungen und Interpreter deutlich kennzeichnen.

## 2.13 Provenienz- und MOTW-Umgehung

**Techniken:**

- Download über Dateisysteme ohne NTFS-Zoneninformation,
- Extraktion, die MOTW nicht vererbt,
- Kopieren über Archive, Images oder Freigaben,
- Umbenennen oder Neuverpacken,
- Browser-/Clientpfade ohne korrekte Herkunftsmarkierung.

**Prüfungen:**

- eigene unveränderliche Provenienz unabhängig vom ADS führen,
- Herkunft über Extraktion, Kopie und Umbenennung vererben,
- Downloadprozess, URL, Zeit, Parent und Hash speichern,
- Verlust der MOTW-Markierung nicht als Vertrauensgewinn behandeln.

## 2.14 Signatur- und Vertrauensmissbrauch

**Techniken:**

- gestohlene Zertifikate,
- abgelaufene, widerrufene oder falsch validierte Signaturen,
- signierte, aber verwundbare Treiber,
- Signatur nur über einen Teil des Containers,
- manipulierte Katalog- oder Manifestbeziehungen,
- vertrauenswürdiger Publisher mit unerwartetem Produkt.

**Prüfungen:**

- vollständige Kette, EKU, Zeitstempel und Revocation,
- Hashbindung jedes relevanten Artefakts,
- Publisher-, Produkt- und Pfadkonsistenz,
- Allowlist nicht nur auf Zertifikatsnamen stützen,
- bekannte verwundbare signierte Komponenten blockieren.

## 2.15 Steganografie und tote Datenbereiche

**Möglichkeiten:**

- Nutzdaten in Bildpixeln, Audio-Samples oder Videoframes,
- Daten hinter logischem Dateiende,
- unreferenzierte PDF-Objekte,
- unbenutzte PE-Sektionen,
- Archiveinträge mit versteckten Namen,
- Metadatenfelder oder Padding.

**Bewertung:**

Steganografische Daten führen nicht automatisch Code aus. Sie können jedoch Konfiguration, Schlüssel, C2-Daten oder eine zweite Stufe für bereits laufende Malware transportieren.

**Prüfungen:**

- unerwartete Entropie und große tote Bereiche,
- Daten hinter formalem Ende,
- unreferenzierte Objekte,
- ungewöhnliches Verhältnis zwischen sichtbarem Inhalt und Dateigröße,
- Korrelation mit Prozessen, die dieselbe Datei lesen und danach Speicher oder Netzwerk verändern.

## 2.16 Cross-Parser-Differenzen

Zwei Komponenten interpretieren dieselbe Datei unterschiedlich.

**Beispiele:**

- Scanner sieht nur den ersten ZIP-Eintrag, Extraktor den letzten,
- doppelte Dateinamen mit unterschiedlichen Schreibweisen,
- Browser und Server bestimmen unterschiedliche MIME-Typen,
- PDF-Reader wählt eine andere Cross-Reference-Tabelle als der Scanner,
- Office repariert eine Struktur, die der statische Parser verwirft.

**Prüfungen:**

- kanonische Interpretation definieren,
- Duplikate und Mehrdeutigkeiten blockieren,
- Parser-Reparaturen protokollieren,
- Ergebnis mindestens eines echten Zielparsers in isolierter Umgebung beobachten,
- bei Abweichung keine automatische Freigabe.

---

# 3. Dateifamilien und konkrete Prüfanforderungen

## 3.1 Native Windows-Programme und Bibliotheken

**Endungen und Formen:**

- `.exe`, `.dll`, `.sys`, `.scr`, `.cpl`, `.ocx`, `.com`, `.drv`, `.efi`
- PE-Dateien mit beliebiger oder fehlender Endung
- ausführbare Inhalte in Ressourcen, Overlays oder Containern

**Mögliche Angriffe:**

- Trojaner, Wurm, Ransomware, Spyware, Loader und Dropper,
- DLL Side-Loading,
- Process Injection,
- Reflective Loading,
- persistente Dienste oder Treiber,
- Credential Theft,
- Netzwerkbeaconing,
- signierte verwundbare Treiber,
- Ressourcen mit zweiter Nutzlast,
- Packers und polymorphe Varianten.

**Zu prüfen:**

- DOS-/PE-Header und alle Offsets,
- Machine Type, Subsystem und Characteristics,
- Abschnittsgrenzen, Rechte und Entropie,
- Import-/Exporttabellen,
- Delay Imports,
- TLS Callbacks,
- Relocations,
- Ressourcen,
- Manifest,
- Debug- und PDB-Pfade,
- Overlay und Daten hinter Zertifikatstabelle,
- Authenticode und Katalogsignatur,
- ungewöhnliche oder fehlende Imports,
- API-Kombinationen für Speicherallokation, Prozessmanipulation, Persistenz, Credential Access und Netzwerk,
- bekannte anfällige Treiber-Hashes,
- Parent-Prozess und Startkontext.

**Enforcement:**

- externe unbekannte Programme niemals allein aufgrund „sauberer“ Signatur freigeben,
- Ausführung über Provenance Execute Gate,
- Child Process, Injection, Treiberladen und Persistenz zur Laufzeit kontrollieren.

## 3.2 Installer und Windows-Pakete

**Endungen:**

- `.msi`, `.msp`, `.mst`, `.msix`, `.appx`, `.appxbundle`, `.msixbundle`
- `.cab`, `.inf`, `.cat`, `.appinstaller`, `.application`, `.appref-ms`

**Mögliche Angriffe:**

- Custom Actions führen Programme oder Skripte aus,
- Installation von Diensten, Treibern, Scheduled Tasks oder Browser-Erweiterungen,
- Repair-/Rollback-Missbrauch,
- Download externer Pakete,
- Pfad- und Rechtefehler,
- Side-Loading,
- manipulierte Paketidentität,
- Downgrade auf verwundbare Versionen.

**Zu prüfen:**

- Paketmanifest und Publisher,
- alle eingebetteten Dateien,
- Custom Actions und Befehlszeilen,
- Zielpfade und Berechtigungen,
- Dienste, Treiber, Tasks, COM-Registrierungen und Autostarts,
- externe Downloadquellen,
- Versionsmonotonie und Downgrade-Schutz,
- Hashbindung zwischen Manifest, Katalog und Payload,
- Installationskontext Benutzer/System.

## 3.3 Skripte und Interpreterdateien

**Endungen:**

- PowerShell: `.ps1`, `.psm1`, `.psd1`
- Windows Script Host: `.vbs`, `.vbe`, `.js`, `.jse`, `.wsf`, `.wsh`
- Shell: `.bat`, `.cmd`
- HTML Application und Scriptlet: `.hta`, `.sct`
- weitere Interpreter: `.py`, `.pyw`, `.pl`, `.rb`, `.php`, `.lua`, `.tcl`, `.sh`
- Konfigurationsdateien, die von Anwendungen als Skript interpretiert werden

**Mögliche Angriffe:**

- Download und Start weiterer Nutzlasten,
- dateilose Ausführung,
- verschleierte Befehle,
- Living-off-the-Land,
- Registry-, WMI-, Task- oder Dienstpersistenz,
- Credential Theft,
- Defender-/Logging-Manipulation,
- lateral movement,
- Interpreter-Chaining.

**Zu prüfen:**

- Encoding und versteckte Unicode-Zeichen,
- Base64, Hex, komprimierte oder dynamische Strings,
- `eval`-/`exec`-ähnliche Konstrukte,
- Prozessstart und Shell-Aufrufe,
- Netzwerk- und Downloadfunktionen,
- Speicherinjektion und Reflection,
- Registry, WMI, Scheduled Tasks und Dienste,
- Sicherheitsprodukt- und Logging-Manipulation,
- Aufrufe typischer Systemwerkzeuge,
- Signatur und Ausführungsrichtlinie,
- MOTW und Herkunft.

**Enforcement:**

- unbekannte externe Skripte blockieren oder isolieren,
- Script Engine Telemetrie mit AMSI/ETW ergänzen,
- obfuskierte Skripte und heruntergeladene Child Payloads blockieren.

## 3.4 Microsoft Word

**Endungen:**

- `.doc`, `.docx`, `.docm`, `.dot`, `.dotx`, `.dotm`
- Word-kompatible RTF- und XML-Formate

**Mögliche Angriffe:**

- VBA-Makros,
- OLE-Objekte und eingebettete Pakete,
- ActiveX,
- externe Templates,
- DDE/DDEAUTO,
- Remote-Bilder und Tracking,
- Hyperlinks und UNC-Pfade,
- eingebettete ausführbare Dateien,
- Parser-/Equation-/Font-Exploits,
- manipulierte OOXML-Relationships,
- Social Engineering zum Aktivieren von Inhalten.

**Zu prüfen:**

- ZIP-Struktur und `[Content_Types].xml`,
- alle Relationship-Dateien,
- `vbaProject.bin`,
- OLE Compound File Streams,
- AutoOpen-/Document_Open-ähnliche Trigger,
- ActiveX-Definitionen,
- DDE-Felder,
- externe Template- und Datenreferenzen,
- OLE Package und Embedded Objects,
- Hyperlinks, UNC/WebDAV und Remote-Bilder,
- Signatur der Makros,
- reparierte oder inkonsistente OOXML-Strukturen,
- eingebettete Fonts und Medien,
- MOTW und Trusted-Location-Kontext.

## 3.5 Microsoft Excel

**Endungen:**

- `.xls`, `.xlsx`, `.xlsm`, `.xlsb`, `.xlt`, `.xltm`, `.xlam`
- `.xll`, `.slk`, `.dif`, `.iqy`, `.odc`, `.udl`
- CSV und tabellarische Importformate

**Mögliche Angriffe:**

- VBA,
- XLM-/Excel-4.0-Makros,
- DDE,
- externe Workbook-Links,
- Power Query und Datenverbindungen,
- OLE/ActiveX,
- Add-ins und native XLL-Dateien,
- Formula Injection,
- Remote-Abfragen,
- sehr große oder komplexe Formeln als DoS,
- Parserfehler in Binär- oder BIFF-Strukturen.

**Zu prüfen:**

- VBA und XLM-Makroblätter,
- definierte Namen und versteckte Blätter,
- Formeln mit externen oder ausführungsrelevanten Funktionen,
- Workbook- und Datenverbindungen,
- Power Query/M-Code,
- DDE und OLE,
- XLL- und Add-in-Referenzen,
- externe Links und UNC-Pfade,
- CSV-Zellen, die bei Export/Öffnen als Formel interpretiert werden,
- Makrosignatur,
- Objektanzahl, Formelkomplexität und Rekursion.

## 3.6 Microsoft PowerPoint

**Endungen:**

- `.ppt`, `.pptx`, `.pptm`, `.potm`, `.ppsm`, `.pps`, `.ppsx`
- Add-ins und eingebettete Medien

**Mögliche Angriffe:**

- VBA,
- OLE/ActiveX,
- automatische Aktionen beim Öffnen oder bei Folienwechsel,
- Hyperlinks und Remote-Medien,
- eingebettete Programme,
- manipulierte Medien-, Font- oder Grafikparser,
- Social Engineering in Präsentationsansicht.

**Zu prüfen:**

- Makros und Signaturen,
- Aktionen an Folien, Formen und Animationen,
- externe Medien und Links,
- OLE Packages,
- eingebettete Dateien und Fonts,
- automatische Präsentationsstarts,
- Child-Process- und Netzwerkverhalten.

## 3.7 OneNote und Notizcontainer

**Endungen:**

- `.one`, `.onepkg` und exportierte OneNote-Pakete

**Mögliche Angriffe:**

- eingebettete ausführbare Dateien, Skripte oder Shortcuts,
- visuell überdeckte Anhänge,
- Hyperlinks,
- Social Engineering zum Start eingebetteter Objekte,
- Container- und Parserfehler.

**Zu prüfen:**

- alle eingebetteten Dateien rekursiv,
- sichtbarer Dateiname gegen tatsächlichen Typ,
- überlagerte oder versteckte Objekte,
- Linkziele,
- Herkunft jedes extrahierten Objekts,
- Ausführung eingebetteter Inhalte blockieren oder bestätigen lassen.

## 3.8 RTF und ältere Office-Binärformate

**Endungen:**

- `.rtf`, `.doc`, `.xls`, `.ppt`, `.pps`, `.dot`, `.xlt`

**Mögliche Angriffe:**

- OLE-Objekte,
- eingebettete Equation-/Package-Objekte,
- Parserfehler,
- verschleierte Hex-Blöcke,
- externe Referenzen,
- Makros in Compound File Streams.

**Zu prüfen:**

- vollständige RTF-Control-Word- und Gruppentiefe,
- Binär- und Hexdaten,
- OLE Streams,
- Objektklassen und CLSIDs,
- ungewöhnliche Verschachtelung,
- Größen- und Rekursionsbudgets,
- jedes eingebettete Objekt separat.

## 3.9 OpenDocument und weitere Office-Formate

**Endungen:**

- `.odt`, `.ods`, `.odp`, `.ott`, `.ots`, `.otp`
- weitere ZIP/XML-basierte Dokumente

**Mögliche Angriffe:**

- Makros und Skripte,
- externe Links, Bilder und Datenquellen,
- eingebettete Objekte,
- XML-/ZIP-Bomben,
- XXE oder XSLT in fehlerhaften Importern,
- Parserfehler.

**Zu prüfen:**

- `META-INF/manifest.xml`,
- Skript- und Macro-Verzeichnisse,
- externe Referenzen,
- eingebettete OLE- oder Binärobjekte,
- XML-Entitäten und externe Schemas,
- Archivbudgets und Pfade.

## 3.10 PDF, FDF und PDF-Portfolios

**Endungen:**

- `.pdf`, `.fdf`, `.xfdf`

**Mögliche Angriffe:**

- Dokument-, Seiten-, Formular- und Annotations-JavaScript,
- `/OpenAction` und `/AA`,
- `/Launch`,
- `/URI`, `/GoToR` und Remote-Aktionen,
- eingebettete Dateien und PDF-Portfolios,
- XFA-Formulare,
- RichMedia und Legacy-Multimedia,
- externe Fonts, Bilder oder Inhalte,
- manipulierte Object Streams und Cross-Reference-Tabellen,
- inkrementelle Updates, die frühere Inhalte verdecken,
- verschlüsselte Objekte,
- Parser- und Font-Exploits,
- Phishing-Formulare.

**Zu prüfen:**

- alle Cross-Reference-Varianten und Revisionen,
- inkrementelle Updates und vorherige Revisionen,
- `/JavaScript`, `/JS`, `/OpenAction`, `/AA`,
- `/Launch`, `/URI`, `/GoToR`, `/SubmitForm`, `/ImportData`,
- EmbeddedFiles Name Tree,
- File Specifications und Attachments,
- XFA und AcroForm,
- RichMedia, Sound, Movie und 3D-Objekte,
- Fonts, Bilder und ICC-Profile,
- Objektstrom- und Dekompressionsbudgets,
- unreferenzierte Objekte und Daten hinter EOF,
- Verschlüsselungsstatus,
- sichtbares Linkziel gegen tatsächliches Ziel.

**Enforcement:**

- JavaScript, Launch und automatische Remote-Aktionen standardmäßig deaktivieren,
- unbekannte PDFs in isoliertem Reader öffnen,
- aktive Inhalte entfernen oder eine rekonstruierte passive Version erzeugen.

## 3.11 XPS, OXPS und Druckdokumente

**Endungen:**

- `.xps`, `.oxps`, `.prn`, `.spl`
- Drucksprachen wie PostScript und PCL

**Mögliche Angriffe:**

- ZIP/XML- und Parserfehler,
- eingebettete Fonts und Bilder,
- externe Ressourcen,
- Druckertreiber- oder Spooler-Angriffsflächen,
- PostScript- oder gerätespezifische Befehle,
- Ressourcenerschöpfung.

**Zu prüfen:**

- Containerstruktur,
- FixedDocument-Relationships,
- Fonts, Bilder und Farbprofile,
- externe Referenzen,
- Druckbefehle und Gerätesteuerung,
- Seiten-, Objekt- und Dekompressionslimits,
- Verarbeitung nur in isoliertem Print-/Renderpfad.

## 3.12 Archive und Kompressionsformate

**Endungen:**

- `.zip`, `.7z`, `.rar`, `.tar`, `.gz`, `.bz2`, `.xz`, `.zst`
- `.cab`, `.arj`, `.ace`, `.lha`, `.lzh`, `.cpio`, `.rpm`
- selbstentpackende Archive und mehrfach verschachtelte Formate

**Mögliche Angriffe:**

- versteckte Malware,
- verschlüsselte Einträge,
- Dekompressionsbomben,
- Zip Slip und absolute Pfade,
- Symlink-/Hardlink-Angriffe,
- NTFS-ADS-Namen,
- doppelte oder kollidierende Dateinamen,
- Parserdifferenzen,
- CRC-/Header-Manipulation,
- selbstentpackender ausführbarer Stub,
- MotW-/Provenienzverlust.

**Zu prüfen:**

- tatsächliches Archivformat,
- alle Einträge und Header,
- komprimierte/entpackte Gesamtgröße,
- Expansionsverhältnis,
- Eintragsanzahl und Rekursionstiefe,
- Pfadnormalisierung,
- Symlinks, Hardlinks und Reparse-Informationen,
- doppelte Namen, Case- und Unicode-Kollisionen,
- verschlüsselte Einträge,
- ausführbare oder aktive Kinder,
- SFX-Stub und Overlay,
- Provenienzvererbung auf jedes Kind.

## 3.13 Disk-Images und virtuelle Datenträger

**Endungen:**

- `.iso`, `.img`, `.vhd`, `.vhdx`, `.wim`, `.esd`, `.udf`
- plattformübergreifend auch `.dmg`

**Mögliche Angriffe:**

- Umgehung von Mark-of-the-Web- oder Anhangsprüfungen,
- darin enthaltene LNK-, Skript-, Installer- oder EXE-Dateien,
- Autorun-/Setup-Köder,
- Dateisystemparserfehler,
- verschachtelte Partitionen,
- manipulierte Bootloader,
- Symlinks und spezielle Dateisystemobjekte.

**Zu prüfen:**

- Partitionstabellen und Dateisysteme,
- Bootsektoren und EFI-Inhalte,
- alle Dateien rekursiv,
- Links und Reparse-ähnliche Objekte,
- Autorun- und Setup-Dateien,
- Volume Labels und UI-Täuschung,
- Provenienz auf gemountete Dateien übertragen,
- Mounten nur read-only und isoliert.

## 3.14 Bilddateien

**Endungen:**

- Raster: `.jpg`, `.jpeg`, `.png`, `.gif`, `.bmp`, `.tif`, `.tiff`, `.webp`
- moderne Container: `.heic`, `.heif`, `.avif`, `.jxl`
- Icons: `.ico`, `.cur`
- Projekte/RAW: `.psd`, `.xcf`, `.raw`, herstellerspezifische RAW-Formate
- Vektor: `.svg`, `.eps`, `.ai`, `.wmf`, `.emf`

**Mögliche Angriffe:**

- Decoder- und Farbprofil-Exploits,
- manipulierte EXIF/IPTC/XMP-Metadaten,
- extrem große Dimensionen oder Framezahlen,
- eingebettete Vorschaubilder,
- Polyglot mit Archiv oder Skript,
- SVG-Skripte, Eventhandler und externe Ressourcen,
- SVG ForeignObject/HTML,
- PostScript in EPS,
- WMF/EMF-Befehle und Parserfehler,
- Steganografie oder angehängte Daten.

**Zu prüfen:**

- Dateisignatur und Chunk-/Segmentstruktur,
- Breite, Höhe, Bittiefe, Framezahl und erwartete Dekodiergröße,
- EXIF/IPTC/XMP und eingebettete Thumbnails,
- ICC-Farbprofile,
- trailing data und zusätzliche Header,
- SVG: Skripte, Eventhandler, externe Links, Data-URIs, ForeignObject,
- EPS/AI: PostScript-Operatoren und externe Dateien,
- Metadatenlängen und Unicode,
- Dekodierung in streng begrenztem Sandboxprozess,
- optional sichere Neuencodierung zur Inhaltsbereinigung.

## 3.15 Audio und Musikdateien

**Endungen:**

- `.wav`, `.wave`, `.mp3`, `.flac`, `.ogg`, `.oga`
- `.aac`, `.m4a`, `.wma`, `.aiff`, `.ape`, `.opus`
- Tracker/MIDI: `.mid`, `.midi`, `.mod`, `.xm`, `.s3m`, `.it`
- Playlists/Begleitdateien: `.m3u`, `.m3u8`, `.pls`, `.asx`, `.wax`, `.wvx`, `.cue`

**Mögliche Angriffe:**

- Codec- oder Containerparser-Exploits,
- manipulierte RIFF-/ID3-/Vorbis-/APE-Metadaten,
- Cover-Art als schädliche Bilddatei,
- extrem große oder inkonsistente Längen,
- Playlist mit Remote-URLs, UNC oder lokalen Pfaden,
- Polyglot-Datei,
- Steganografische zweite Stufe,
- Tracker-/MIDI-Parserfehler,
- Anwendungsaktionen aufgrund proprietärer Metadaten.

**Zu prüfen:**

- RIFF/FORM/MP4/ASF/Ogg-Struktur,
- Chunk- und Frame-Längen,
- Codec-ID gegen tatsächliche Daten,
- ID3, APEv2, Vorbis Comments und proprietäre Tags,
- eingebettete Bilder separat,
- Dauer, Samplezahl, Kanäle und erwartete Dekodiergröße,
- Playlists: jedes Ziel, URI-Schema, UNC und Pfadnormalisierung,
- externe Ressourcen nicht automatisch laden,
- Daten hinter logischem Streamende,
- Sandbox-Dekodierung ohne Netzwerkzugriff.

## 3.16 Video und Mediencontainer

**Endungen:**

- `.mp4`, `.mov`, `.m4v`, `.avi`, `.mkv`, `.webm`
- `.mpeg`, `.mpg`, `.ts`, `.m2ts`, `.wmv`, `.asf`, `.flv`
- Projekt- und Streaming-Manifeste

**Mögliche Angriffe:**

- Container-, Codec-, Untertitel- oder Font-Exploits,
- manipulierte Atom-/Box-/Chunk-Längen,
- eingebettete Attachments in Matroska,
- externe Tracks, Playlists oder Streaming-URLs,
- Cover-Art und Thumbnails,
- extrem viele Tracks, Frames oder Kapitel,
- Polyglot und trailing payload,
- Steganografische Daten.

**Zu prüfen:**

- Containerhierarchie und Offsets,
- Track- und Codecdeklarationen,
- Dauer, Framerate, Auflösung und erwartete Dekodierlast,
- eingebettete Untertitel, Fonts, Bilder und Attachments,
- Kapitel- und Metadaten-URLs,
- HLS/DASH-Manifestziele,
- externe Referenzen,
- sichere, budgetierte Sandbox-Dekodierung.

## 3.17 Untertitel und Medienbegleitdateien

**Endungen:**

- `.srt`, `.vtt`, `.ass`, `.ssa`, `.sub`, `.idx`, `.ttml`

**Mögliche Angriffe:**

- Parserfehler,
- sehr große oder komplexe Stylingdaten,
- eingebettete Fonts oder Attachments über Container,
- HTML-/Markup-Missbrauch,
- externe Referenzen,
- Social Engineering über eingeblendete Links.

**Zu prüfen:**

- Encoding und Längen,
- Zeitstempelreihenfolge,
- Tags, Styles und Skriptähnliches,
- externe Ressourcen,
- Dateigröße und Ereignisanzahl,
- Renderer in isoliertem Prozess.

## 3.18 Fonts

**Endungen:**

- `.ttf`, `.otf`, `.ttc`, `.woff`, `.woff2`, `.eot`
- Type1: `.pfb`, `.pfa`
- eingebettete Fonts in Dokumenten, PDFs, Bildern und Videos

**Mögliche Angriffe:**

- Fehler in Fontparsern und Rasterizern,
- manipulierte Tabellen und Glyphprogramme,
- Dekompressions- und Rekursionsangriffe,
- extrem komplexe Konturen,
- externe Fontreferenzen,
- Font-Spoofing.

**Zu prüfen:**

- Tabellenverzeichnis, Offsets und Checksummen,
- Glyphanzahl und Konturkomplexität,
- Hinting-/Glyphprogramme,
- WOFF-Kompressionsbudgets,
- Namens- und Unicode-Tabellen,
- Signatur beziehungsweise Herkunft,
- Parsing ausschließlich isoliert.

## 3.19 HTML, MHTML und Webdokumente

**Endungen:**

- `.html`, `.htm`, `.xhtml`, `.mht`, `.mhtml`
- `.svg` bei Browserdarstellung
- Webarchive und gespeicherte Webseiten

**Mögliche Angriffe:**

- JavaScript und WebAssembly,
- Browser-Exploits,
- HTML Smuggling,
- Base64-/Blob-/Data-URI-Nutzlasten,
- Iframes und Redirects,
- Phishing-Formulare,
- Credential Harvesting,
- Downloads und Custom URI Handler,
- Service Worker oder persistenter Webspeicher im passenden Kontext,
- externe Ressourcen und Tracking,
- eingebettete Dateien in MHTML.

**Zu prüfen:**

- Skripte, Module und WebAssembly,
- Eventhandler und dynamische Codeausführung,
- Iframes, Forms, Meta Refresh und Redirects,
- Download-Attribute und erzeugte Blobs,
- Data-URIs und große kodierte Blöcke,
- externe Hosts, IP-Literale und IDN,
- Custom-Schemes,
- MHTML-MIME-Teile,
- Sandboxbrowser ohne Zugriff auf interne Netze oder Benutzerprofile,
- Content Security Policy für rekonstruierte Darstellung.

## 3.20 XML, XSLT und Schemaformate

**Endungen:**

- `.xml`, `.xsl`, `.xslt`, `.xsd`, `.svg`, `.config`
- anwendungsspezifische XML-Container

**Mögliche Angriffe:**

- externe Entitäten und XXE,
- Billion-Laughs-/Entity-Expansion,
- externe DTDs und Schemas,
- XSLT-Skript- oder Erweiterungsfunktionen,
- XPath-/Parserkomplexität,
- SSRF-artige Netzwerkzugriffe,
- lokale Dateioffenlegung,
- Parserdifferenzen.

**Zu prüfen:**

- DTD und externe Entitäten standardmäßig deaktivieren,
- externe Schema-/XInclude-Referenzen,
- Entity-, Knoten-, Attribut- und Tiefenlimits,
- XSLT-Erweiterungen und Skriptfunktionen,
- Namespace- und Encoding-Konsistenz,
- keine Netzwerknutzung im Parser.

## 3.21 JSON, YAML, TOML und Konfigurationen

**Endungen:**

- `.json`, `.jsonl`, `.yaml`, `.yml`, `.toml`, `.ini`, `.conf`
- Anwendungskonfigurationen und Manifeste

**Mögliche Angriffe:**

- unsichere Deserialisierung,
- YAML-Tags mit Objektkonstruktion,
- Prototype Pollution in nachgelagerten JavaScript-Systemen,
- sehr tiefe oder große Objektstrukturen,
- doppelte Schlüssel mit Parserdifferenzen,
- Pfad-, Kommando- oder Template-Injektion,
- externe Referenzen in anwendungsspezifischen Feldern.

**Zu prüfen:**

- Schema und erlaubte Schlüssel,
- doppelte Schlüssel,
- maximale Tiefe, Größe und Zahl der Elemente,
- YAML-Tags/Typkonstruktoren,
- URLs, Pfade und Befehlsfelder,
- kanonische Serialisierung vor Signaturprüfung,
- Konfigurationswerte nie direkt an Shell weitergeben.

## 3.22 Serialisierte Objekte und Sprachartefakte

**Endungen/Formate:**

- Python Pickle: `.pkl`, `.pickle`, `.joblib`
- Java Serialization, `.ser`
- .NET BinaryFormatter-artige Daten
- PHP-Serialisierung
- Ruby Marshal
- framework- und anwendungsspezifische Objektstreams

**Mögliche Angriffe:**

- Codeausführung während Deserialisierung,
- Gadget Chains,
- Objektgraph- und Speicherbomben,
- unerwartete Klasseninstanziierung,
- Dateisystem- und Netzwerkaktionen beim Laden.

**Zu prüfen:**

- unsichere generische Deserialisierung grundsätzlich vermeiden,
- Format nur in isoliertem Prozess untersuchen,
- Klassen-/Typ-Allowlist,
- keine Konstruktoren, Hooks oder Callbacks ausführen,
- Objektanzahl, Tiefe und Größe begrenzen,
- Herkunft und Signatur verlangen.

## 3.23 CSV, TSV und tabellarische Textdaten

**Endungen:**

- `.csv`, `.tsv`, `.txt` mit Tabellenstruktur

**Mögliche Angriffe:**

- Formula Injection bei Öffnung in Tabellenkalkulation,
- DDE- oder Hyperlinkformeln,
- Encoding-/Delimiter-Täuschung,
- sehr große Zeilen oder Spalten,
- Injektion in Importpipelines,
- Steuerzeichen und unsichtbare Unicode-Zeichen.

**Zu prüfen:**

- Zellen, die mit Formelpräfixen beginnen,
- Hyperlinks und externe Referenzen,
- maximale Zeilen-/Spalten-/Feldgröße,
- Encoding und Steuerzeichen,
- Zielanwendung berücksichtigen,
- sichere Escape-/Neutralisierungsstrategie bei Export.

## 3.24 Datenbanken und Datencontainer

**Endungen:**

- `.mdb`, `.accdb`, `.sqlite`, `.db`, `.db3`
- Datenbankdumps und Backupformate

**Mögliche Angriffe:**

- Access-Makros, VBA und Action Queries,
- verknüpfte Tabellen und externe Datenquellen,
- Parserfehler,
- schädliche Trigger oder Views für Importwerkzeuge,
- Erweiterungs- oder Plugin-Laden,
- Ressourcenerschöpfung durch manipulierte Indizes,
- SQL-Injektion in unsicheren Importpfaden.

**Zu prüfen:**

- Makros, Module und Startobjekte,
- externe Verbindungen,
- Trigger, Views und benutzerdefinierte Funktionen,
- Extension-Loading deaktivieren,
- Seiten-/Indexstruktur und Größenbudgets,
- Import nur in isolierte temporäre Datenbank.

## 3.25 E-Mail- und Nachrichtencontainer

**Endungen:**

- `.eml`, `.msg`, `.mbox`, `.pst`, `.ost`, `.dbx`, `.mbx`
- `.dat`/TNEF wie `winmail.dat`
- MIME-Nachrichten ohne Endung

**Mögliche Angriffe:**

- verschachtelte Anhänge,
- HTML-Phishing,
- Remote-Trackingpixel,
- MIME-Smuggling und Parserdifferenzen,
- eingebettete Archive,
- verschlüsselte oder passwortgeschützte Anhänge,
- Kalender-, Kontakt- und Formularobjekte,
- Header-Injektion,
- Vorschau-Exploits.

**Zu prüfen:**

- MIME-Boundaries und Content-Transfer-Encoding,
- Diskrepanz zwischen Content-Type, Name und tatsächlichem Format,
- alle Attachments rekursiv,
- HTML, Links, Formulare und externe Bilder,
- TNEF-Inhalte,
- verschachtelte Nachrichten,
- Unicode-/IDN-Absender und Reply-To-Differenzen,
- Authentifizierungsresultate als Kontext, nicht als Dateivertrauen,
- Preview in Isolation.

## 3.26 Kalender und Kontakte

**Endungen:**

- `.ics`, `.vcs`, `.vcf`

**Mögliche Angriffe:**

- Phishing-Links,
- Remote-Meeting- oder Attachment-URLs,
- automatische Kalenderverarbeitung,
- sehr große oder rekursive Wiederholungsregeln,
- Parserfehler,
- Unicode-Täuschung,
- Custom URI Handler.

**Zu prüfen:**

- Organizer, Attendee, URL und Attach-Felder,
- Wiederholungs- und Zeitzonenkomplexität,
- eingebettete oder externe Attachments,
- sichtbarer Name gegen tatsächliche Domain,
- automatische Annahme und externe Ressourcen deaktivieren.

## 3.27 Windows-Shortcuts und Shell-Dateien

**Endungen:**

- `.lnk`, `.url`, `.website`, `.scf`
- `.library-ms`, `.search-ms`, `.settingcontent-ms`
- `.contact`, `.desklink` und shellbezogene Spezialformate

**Mögliche Angriffe:**

- Start beliebiger Programme mit Argumenten,
- verschleierte Befehlszeilen,
- Remote-Icons oder UNC/WebDAV-Zugriffe,
- Credential-Leak,
- DLL Side-Loading über Working Directory,
- Ausführung von Systemwerkzeugen,
- Icon-Spoofing,
- Tracking und zweite Stufen.

**Zu prüfen:**

- Zielpfad, Argumente, Arbeitsverzeichnis und Iconpfad,
- relative, UNC-, WebDAV- und Netzwerkziele,
- Environment Expansion,
- eingebettete Tracker- und Shell-Items,
- tatsächlicher Zieltyp,
- Zielsignatur und Provenienz,
- externe Shortcuts standardmäßig blockieren oder bestätigen lassen.

## 3.28 Hilfe-, Dokumentations- und Legacy-Container

**Endungen:**

- `.chm`, `.hlp`, `.hta`, `.mht`
- Microsoft Compiled HTML Help und verwandte Formate

**Mögliche Angriffe:**

- HTML/JavaScript,
- ActiveX und Script Bridges,
- Start lokaler Programme,
- eingebettete Dateien,
- Remote-Links,
- Parserfehler und Zonenmissbrauch.

**Zu prüfen:**

- dekompilierte HTML-/Scriptinhalte,
- ActiveX- und Objektaufrufe,
- Befehls-/Prozessstart,
- externe Ressourcen,
- alle eingebetteten Dateien,
- Herkunft und MOTW,
- Öffnen nur in isolierter Umgebung.

## 3.29 Registry-, Richtlinien- und Systemkonfigurationsdateien

**Endungen:**

- `.reg`, `.pol`, `.inf`, `.adm`, `.admx`, `.adml`
- Dienst-, Task-, Firewall-, VPN- oder Security-Konfigurationen

**Mögliche Angriffe:**

- Autostart und Persistenz,
- Sicherheitsabsenkung,
- Dateizuordnungs- und Shell-Hijacking,
- COM-Hijacking,
- Treiber- oder Dienstinstallation,
- Firewall-/Proxy-/DNS-Manipulation,
- Defender-/Logging-Ausnahmen,
- Credential- oder Zertifikatimport.

**Zu prüfen:**

- alle Zielschlüssel und Werte,
- sicherheitsrelevante Policies,
- Autostart-, IFEO-, COM-, Service- und Shell-Pfade,
- Dateipfade und Befehlszeilen,
- Privilegbedarf,
- transaktionale Anwendung mit Rollback,
- niemals stille Anwendung externer Konfigurationen.

## 3.30 Zertifikate, Schlüssel und Verbindungsprofile

**Endungen:**

- `.pfx`, `.p12`, `.pem`, `.key`, `.cer`, `.crt`, `.der`
- `.rdp`, VPN-Profile, WLAN-Profile, SSH-Konfigurationen

**Mögliche Angriffe:**

- Installation eines schädlichen Root-Zertifikats,
- Import privater Schlüssel,
- Verbindung zu Angreifersystemen,
- schwache oder manipulierte Profile,
- Credential-Weitergabe,
- unerwartete Smartcard-/Provider-Konfiguration,
- Trust-Store-Manipulation.

**Zu prüfen:**

- Zertifikatstyp, Basic Constraints, EKU und Chain,
- ob private Schlüssel enthalten sind,
- Ziel-Trust-Store und Installationskontext,
- RDP-/VPN-/SSH-Ziel, Gateway und Redirect-Einstellungen,
- Credential- und Laufwerksweiterleitung,
- Signatur des Profils,
- Import nur mit ausdrücklicher administrativer Bestätigung.

## 3.31 Java-Archive und JVM-Artefakte

**Endungen:**

- `.jar`, `.war`, `.ear`, `.class`, `.jnlp`

**Mögliche Angriffe:**

- direkte Codeausführung,
- statische Initializer,
- manipulierte Manifeste,
- eingebettete native Bibliotheken,
- unsichere Deserialisierung,
- Dependency Confusion,
- signierte, aber unerwartete Klassen,
- ZIP-basierte Containerangriffe.

**Zu prüfen:**

- Manifest und Main-Class,
- alle Klassen und Ressourcen,
- native Libraries,
- Signaturen aller Einträge,
- doppelte Namen und Multi-Release-Inhalte,
- Deserialisierungsnutzung,
- Netzwerk-, Prozess- und Dateisystem-APIs,
- Archivbudgets.

## 3.32 .NET-Assemblies und NuGet-Pakete

**Endungen:**

- `.dll`, `.exe`, `.nupkg`, `.snupkg`
- `.deps.json`, `.runtimeconfig.json`

**Mögliche Angriffe:**

- Managed Malware,
- Module Initializers,
- Reflection und dynamisches Laden,
- P/Invoke und native Payloads,
- Build-/Installationsskripte in Paketen,
- Dependency Confusion,
- Typosquatting,
- manipulierte Signaturen.

**Zu prüfen:**

- CLR-Metadaten und Entry Points,
- Module Initializers,
- P/Invoke,
- Reflection.Emit und dynamische Assemblyloads,
- eingebettete Ressourcen,
- Paketmanifest, Autoren, Repository und Signaturen,
- Build-/Install-/PowerShell-Inhalte,
- Abhängigkeitsquellen und Versionsbindung.

## 3.33 Entwickler-, Build- und Projektdateien

**Formate:**

- Visual Studio: `.sln`, `.vcxproj`, `.csproj`, `.props`, `.targets`
- CMake, Make, Ninja und Buildskripte
- VS Code Workspaces, Tasks und Extensions
- Git-Konfiguration und Hooks
- Dockerfiles, Compose und Devcontainer
- CI/CD-Pipelines
- IDE-Projekte anderer Hersteller

**Mögliche Angriffe:**

- automatische Build-Schritte,
- Pre-/Post-Build-Commands,
- Import externer Targets,
- Task-Ausführung beim Öffnen oder Bauen,
- schädliche IDE-Erweiterungen,
- Credential Theft aus Buildumgebung,
- Dependency Confusion,
- Container- oder CI-Secrets-Exfiltration.

**Zu prüfen:**

- alle Befehle und Script Hooks,
- externe Imports und Paketquellen,
- Toolchain-Dateien,
- Pre-/Post-Build und Custom Targets,
- IDE-Tasks und Launch-Konfigurationen,
- Git-Hooks und Submodule,
- Container-Entrypoints und Mounts,
- Netzwerkziele,
- Öffnen eines fremden Projekts nicht als passive Aktion behandeln.

## 3.34 Paketmanager- und Softwarelieferkettenartefakte

**Formate:**

- npm-Pakete und `package.json`,
- Python Wheels und Source Distributions,
- NuGet,
- Maven/Gradle,
- Ruby Gems,
- Rust Crates,
- native Paketformate,
- Plugin- und Extension-Pakete.

**Mögliche Angriffe:**

- Install-, Postinstall- oder Buildskripte,
- Dependency Confusion,
- Typosquatting,
- kompromittierte Maintainer,
- manipulierte Lockfiles,
- native Add-ons,
- Download weiterer Binärdateien,
- exfiltrierende Build Hooks.

**Zu prüfen:**

- Paketname, Namespace, Registry und Publisher,
- Signatur, Provenance und Reproducibility,
- Lifecycle Scripts,
- native Binärdateien,
- externe Downloads,
- Lockfile-Integrität,
- unerwartete neue Abhängigkeiten,
- Berechtigungen und Netzwerkzugriff während Build/Install.

## 3.35 KI-/ML-Modell- und Gewichtsdateien

**Formate:**

- unsichere Objektformate: Pickle, Joblib, manche Framework-Checkpoints
- Container: `.pt`, `.pth`, `.ckpt`, `.onnx`, `.safetensors`, `.gguf`
- Tensor-, Tokenizer-, Konfigurations- und Custom-Operator-Dateien

**Mögliche Angriffe:**

- Codeausführung beim Deserialisieren,
- Custom Operators oder Plugins,
- externe Datenreferenzen,
- ZIP-/Containerangriffe,
- extrem große Tensoren als Speicherangriff,
- manipulierte Tokenizer oder Konfigurationen,
- Model Poisoning und Backdoors,
- versteckte Instruktionen oder Daten,
- Loader-Parserfehler.

**Zu prüfen:**

- tatsächliches Containerformat,
- keine generische unsichere Deserialisierung,
- Tensorzahl, Shapes, Datentypen und Gesamtspeicher,
- externe Datenpfade,
- Custom Ops und dynamische Libraries,
- Tokenizer-Skripte und Templates,
- Signatur und Modellmanifest,
- reproduzierbare Herkunft,
- Modellverhalten zusätzlich in isolierten Tests evaluieren.

## 3.36 CAD-, 3D-, BIM- und Konstruktionsdateien

**Endungen:**

- `.dwg`, `.dxf`, `.dwf`, `.step`, `.stp`, `.iges`, `.igs`
- `.stl`, `.obj`, `.fbx`, `.gltf`, `.glb`, `.3mf`
- `.blend` und anwendungsspezifische Projektdateien

**Mögliche Angriffe:**

- Parserfehler,
- eingebettete Skripte oder Makros,
- externe Referenzen, Texturen, Fonts und Bibliotheken,
- ZIP-basierte 3MF-Angriffe,
- extrem komplexe Geometrie als DoS,
- Plugin-/Renderer-Angriffe,
- manipulierte Projekt-Startaktionen.

**Zu prüfen:**

- Geometrie-, Objekt- und Polygonbudgets,
- externe Referenzen,
- eingebettete Skripte und Plugins,
- Materialien, Texturen, Bilder und Fonts separat,
- Containerpfade,
- Sandbox-Import ohne Netzwerk und ohne Projekt-Startup-Code.

## 3.37 G-Code, CNC- und Maschinensteuerdateien

**Endungen:**

- `.gcode`, `.nc`, `.tap` und herstellerspezifische Formate

**Mögliche Angriffe:**

- physische Fehlbewegungen,
- Temperatur-, Geschwindigkeits- oder Grenzwertüberschreitung,
- Deaktivierung von Sicherheitsfunktionen,
- unerwartete Firmwarebefehle,
- versteckte Befehle in Kommentaren oder Makros,
- Ressourcenverbrauch und Geräteschäden.

**Zu prüfen:**

- Befehls-Allowlist,
- Maschinenprofil und harte Grenzwerte,
- Bewegungs-, Temperatur-, Spindel- und Leistungsgrenzen,
- Firmware-/Herstellerkommandos,
- Simulation vor Ausführung,
- kryptografische Jobfreigabe für kritische Anlagen.

## 3.38 GIS-, Karten- und Geodaten

**Endungen/Formate:**

- Shapefile-Komponenten, GeoJSON, KML/KMZ, GeoTIFF
- Projektdateien und Styles

**Mögliche Angriffe:**

- ZIP/XML-/JSON-Parserangriffe,
- externe Bilder, Tiles und Netzwerkquellen,
- Projekt-Plugins oder Ausdrücke,
- extrem große Geometrien,
- Pfadmanipulation über Begleitdateien,
- eingebettete Skripte in anwendungsspezifischen Projekten.

**Zu prüfen:**

- alle zusammengehörigen Sidecar-Dateien,
- externe Datenquellen,
- Styles und Expressions,
- Geometriekomplexität,
- KMZ als Archiv,
- Projektstart-Plugins und Skripte.

## 3.39 E-Books und Publikationscontainer

**Endungen:**

- `.epub`, `.mobi`, `.azw`, `.azw3`, `.fb2`

**Mögliche Angriffe:**

- HTML, CSS, JavaScript je nach Reader,
- externe Links und Tracking,
- eingebettete Fonts, Bilder und Medien,
- ZIP-/XML-Angriffe,
- Reader-Parserfehler,
- Social Engineering.

**Zu prüfen:**

- Container und Manifest,
- HTML/SVG/Skripte,
- externe Ressourcen,
- Fonts und Bilder,
- Rekursions- und Größenbudgets,
- Reader-Isolation.

## 3.40 Torrent-, Playlist- und Linkcontainer

**Endungen:**

- `.torrent`, `.m3u`, `.pls`, `.asx`
- Link- und Feeddateien

**Mögliche Angriffe:**

- automatische Netzwerkverbindungen,
- Tracker- und Peer-Kontakte,
- UNC-/WebDAV-/HTTP-Ziele,
- lokale Pfadreferenzen,
- Parserfehler,
- Phishing oder Download zweiter Stufen.

**Zu prüfen:**

- alle Netzwerkziele,
- Protokolle und Ports,
- lokale/remote Pfade,
- automatische Aktion versus Benutzerbestätigung,
- keine Netzwerkverbindung allein durch Vorschau.

## 3.41 Firmware-, BIOS- und Geräteupdate-Dateien

**Formate:**

- UEFI Capsules,
- BIOS-/EC-/SSD-/GPU-/Router-Firmware,
- Option ROMs,
- Geräteherstellerpakete

**Mögliche Angriffe:**

- persistente Firmwaremanipulation,
- Downgrade,
- falsches Gerätemodell,
- schädliche signierte Updates,
- manipulierte Updater,
- Bootkits,
- physische Funktionsbeeinträchtigung.

**Zu prüfen:**

- Hersteller- und Plattformidentität,
- kryptografische Signatur,
- Anti-Rollback-Version,
- Hardwaremodell und Board-ID,
- Hash gegen Herstellerkanal,
- Updateprogramm separat,
- Offline-/Recovery-Plan,
- niemals generisch automatisch flashen.

## 3.42 Browsererweiterungen, IDE-Plugins und Add-ins

**Endungen/Formate:**

- `.crx`, `.xpi`, `.vsix`
- Office Add-ins, COM Add-ins und anwendungsspezifische Plugins

**Mögliche Angriffe:**

- Zugriff auf Webseiten, Tokens, Dateien und Zwischenablage,
- Native Messaging,
- Updatekanalübernahme,
- Credential Theft,
- Codeausführung im Host,
- persistente Erweiterung,
- Supply-Chain-Angriff.

**Zu prüfen:**

- Manifest und Berechtigungen,
- Host Permissions,
- Content Scripts,
- Native Messaging Hosts,
- externe Update-URLs,
- Signatur und Store-Herkunft,
- eingebettete native Binärdateien,
- minimale Berechtigungen erzwingen.

## 3.43 Speicherstände, Mods und Spieldateien

**Formate:**

- Mods, Plugins, Maps, Savegames, Workshop-Pakete

**Mögliche Angriffe:**

- native oder verwaltete Plugins,
- Skripte,
- Parserfehler in Savegames und Maps,
- eingebettete Assets,
- Archive und externe Downloads,
- Supply-Chain-Angriffe über Mod-Plattformen.

**Zu prüfen:**

- Code-/Pluginanteile,
- Skripte,
- Container und Assets,
- Engine-spezifische Startup Hooks,
- Signatur und Publisher,
- Sandbox oder eingeschränkter Spielprozess.

---

# 4. Dateinamen, Erweiterungen und Tarnung

AI Shield muss vor jeder Formatprüfung folgende Tarnindikatoren auswerten:

- doppelte Erweiterung wie `rechnung.pdf.exe`,
- viele Leerzeichen vor der tatsächlichen Erweiterung,
- Right-to-Left-Override und andere bidirektionale Steuerzeichen,
- ähnlich aussehende Unicode-Zeichen,
- nachgestellte Punkte oder Leerzeichen,
- fehlende Erweiterung,
- falsche MIME-Angabe,
- Icon, das nicht zum tatsächlichen Typ passt,
- ausführbare Dateien mit Dokumentendung,
- ADS wie `harmlos.txt:payload.exe`,
- reservierte Gerätenamen,
- sehr lange Namen zur UI-Abschneidung,
- Case- und Normalisierungskollisionen,
- Nullbyte- oder Trennzeichenprobleme in nachgelagerten APIs,
- versteckte/systemgeschützte Attribute,
- Shortcut, dessen sichtbarer Name das Ziel verschleiert.

**Entscheidungsregel:** Eine Diskrepanz zwischen sichtbarem Namen, Erweiterung, MIME, Magic Bytes und Parserklassifikation erhöht den Risikowert erheblich und verhindert eine automatische Freigabe.

---

# 5. Verbindliche Scan-Pipeline für AI Shield

## Stufe 0 – Aufnahme und Provenienz

Erfassen:

- vollständiger SHA-256-Hash,
- Dateigröße,
- File-ID und Volume-ID,
- Erstellungs- und Downloadzeit,
- Quellprozess,
- Parent-Prozess,
- Download-URL und Referrer, soweit vorhanden,
- E-Mail-/Browser-/USB-/Netzwerk-/Cloud-Herkunft,
- MOTW/Zone Identifier,
- Signaturzustand,
- Container-Parent und Extraktionspfad.

Die Provenienz muss unabhängig von NTFS Alternate Data Streams im AI-Shield-Store fortbestehen.

## Stufe 1 – Identitäts- und Polyglot-Prüfung

- Dateiendung,
- deklarierter MIME-Typ,
- Magic Bytes,
- interne Formatkennung,
- zusätzliche Header an anderen Offsets,
- trailing data,
- Overlay,
- mehrere plausible Parser,
- widersprüchliche Größen- oder Endmarken.

Ergebnis darf nicht nur „PDF“ lauten, sondern beispielsweise:

`PDF + ZIP-Trailer + JavaScript + eingebettete PE-Datei + externe URI`.

## Stufe 2 – Sichere Containerzerlegung

- rekursiv, aber budgetiert,
- kein Schreiben außerhalb eines isolierten Roots,
- keine Linkverfolgung,
- keine Ausführung,
- keine Netzwerknutzung,
- keine automatische Passwortübernahme,
- jedes Kind erhält eigene Identität, Hash und Provenienz,
- Parent-Child-Graph in Audit und Causal Chain speichern.

## Stufe 3 – Strikte Strukturvalidierung

Für jedes Format:

- Header,
- Version,
- Offsets,
- Längen,
- Tabellen,
- Checksummen,
- Objektgraph,
- Referenzen,
- Kompressionsdaten,
- Zeichensätze,
- doppelte oder überlappende Strukturen,
- Reparaturbedarf.

Ein Parser, der eine Datei „repariert“, darf diese Reparatur nicht stillschweigend als sauber einstufen.

## Stufe 4 – Extraktion aktiver Fähigkeiten

AI Shield muss nicht nur Zeichenketten suchen, sondern Fähigkeiten extrahieren:

- Script vorhanden,
- Script startet automatisch,
- Child Process möglich,
- Netzwerkzugriff möglich,
- externer Inhalt vorhanden,
- Dateiablage möglich,
- Registry-/Policyänderung möglich,
- eingebettete ausführbare Datei vorhanden,
- Interpreter oder LOLBin referenziert,
- Credential-/Authentifizierungsfluss möglich,
- Drucker-/Geräteaktion möglich,
- Installation oder Persistenz möglich.

## Stufe 5 – Statische Erkennung

- bekannte Hashes und Signaturen,
- YARA-/Signatur-ähnliche Byte- und Strukturregeln,
- Import-/API- und Befehlsindikatoren,
- Entropie,
- Packing,
- N-Gramme und Sequenznovelty,
- SimHash/Ähnlichkeit,
- bekannte Kampagnenmuster,
- URL-/Domain-/Zertifikatsreputation,
- anomalieorientierte Merkmale.

Statische Erkennung allein darf keine vollständige Sicherheitsgarantie darstellen.

## Stufe 6 – Isolierte Zielparser- und Verhaltensanalyse

Für risikoreiche oder unbekannte Dateien:

- echter Zielparser oder kompatibler Viewer im AppContainer,
- kein Zugriff auf Benutzerprofil oder produktive Daten,
- standardmäßig kein Netzwerk,
- Job Object mit Prozess-, Speicher- und Zeitlimit,
- Child Processes blockieren oder vollständig instrumentieren,
- Dateisystem-/Registry-/Prozess-/Netzwerk-/IPC-Ereignisse erfassen,
- Parserabsturz als verdächtig markieren,
- mehrere Trigger testen: Öffnen, Vorschau, Seitenwechsel, Drucken, Speichern, Export, Entpacken und Schließen.

## Stufe 7 – Content Disarm and Reconstruction

Für unterstützte Formate kann AI Shield eine passive Version erzeugen:

- Bilder dekodieren und neu encodieren,
- PDF ohne JavaScript, Launch, Attachments und externe Aktionen rekonstruieren,
- Office-Dokument ohne Makros, OLE, ActiveX und externe Relationships erzeugen,
- Archive neu packen, nur nach vollständiger Prüfung,
- Metadaten minimieren,
- Original niemals überschreiben,
- Hash und Transformationsbericht speichern.

## Stufe 8 – Laufzeit-Consequence-Gates

Auch eine freigegebene Datei bleibt unter Beobachtung.

Blockierbare Konsequenzen:

- Viewer startet Shell, Script Engine oder Systemwerkzeug,
- Office/PDF/Browser erzeugt Child Process,
- unbekannter Prozess lädt ausführbaren Inhalt aus Temp/Downloads,
- Prozess schreibt in Autostart-, Service-, Treiber- oder Systempfade,
- Prozess injiziert in andere Prozesse,
- Datei löst unerwartete Netzwerkverbindung aus,
- Dokument greift auf UNC/WebDAV zu,
- Parser öffnet weitere lokale vertrauliche Dateien,
- Prozess deaktiviert Sicherheitsfunktionen,
- unbekannter Treiber soll geladen werden.

## Stufe 9 – Entscheidung

Empfohlene Ergebniszustände:

1. **ALLOW**  
   Strukturell valide, keine aktiven Fähigkeiten, vertrauenswürdige Provenienz, keine Anomalien.

2. **ALLOW_WITH_MONITORING**  
   Geringes Restrisiko; Laufzeitüberwachung bleibt aktiv.

3. **SANITIZE_AND_ALLOW**  
   Aktive oder unnötige Bestandteile werden entfernt; nur rekonstruierte Version wird geöffnet.

4. **OPEN_IN_ISOLATION**  
   Unbekannt, verschlüsselt, komplex oder mit legitimen aktiven Bestandteilen.

5. **USER_CONFIRM_HIGH_RISK**  
   Geschäftlich erforderlich, aber mit klar erklärter Fähigkeit und Folge.

6. **QUARANTINE**  
   Nicht ausreichend prüfbar, verdächtig, verschlüsselt oder mit nicht erlaubter Nutzlast.

7. **BLOCK**  
   bestätigte Schadfunktion, Policyverstoß, Exploitindikator oder verbotene Konsequenz.

---

# 6. Globale Scan-Grenzwerte

Die Werte müssen konfigurierbar und je Format anpassbar sein. Mindestkategorien:

- maximale Eingabedateigröße,
- maximale entpackte Gesamtgröße,
- maximales Expansionsverhältnis,
- maximale Archivtiefe,
- maximale Zahl extrahierter Objekte,
- maximale XML-/JSON-/Objekttiefe,
- maximale Bilddimension und Pixelzahl,
- maximale Audio-/Videodauer,
- maximale Frame-, Track- und Seitenzahl,
- maximale Font-/Glyphkomplexität,
- maximale Formel- und Workbook-Komplexität,
- maximale CPU-Zeit,
- maximales Working Set,
- maximale Handle-, Thread- und Child-Process-Zahl,
- maximale Netzwerkziele in Sandbox,
- maximale Zahl externer Referenzen,
- maximale String- und Metadatenlänge,
- maximale Zahl parserbedingter Reparaturen,
- maximale Zahl widersprüchlicher Formatindikatoren.

Ein Budgetabbruch ist kein „sauber“-Ergebnis.

---

# 7. Risikoindikatoren mit hoher Priorität

Unabhängig vom Format sollten folgende Merkmale den Risikowert stark erhöhen:

- ausführbarer Inhalt in einem Dokument- oder Mediencontainer,
- automatische Open-/Launch-/Script-Aktion,
- Child Process aus Office, PDF-Reader, Browser, Archivprogramm oder Medienplayer,
- externe UNC-/WebDAV-Referenz,
- verschlüsselte aktive Inhalte,
- Polyglot oder widersprüchliche Formatklassifikation,
- Daten hinter formalem Dateiende,
- eingebettete LNK-, HTA-, CHM-, Skript-, MSI-, DLL-, EXE- oder Treiberdatei,
- nicht signierter oder unerwarteter Treiber,
- signierter bekannter verwundbarer Treiber,
- Makro plus Download-/Prozessstartfähigkeit,
- DDE, XLM-Makros oder externe Templates,
- PDF JavaScript plus OpenAction oder Launch,
- Archiv mit Traversal, Links oder extremer Expansion,
- SVG mit Skript oder externer Ressource,
- Playlist mit UNC/WebDAV oder unerwartetem Remoteziel,
- Shortcut mit Remote-Icon oder verschleierter Befehlszeile,
- unbekannte Datei aus E-Mail/Browser ohne belastbare Provenienz,
- Parsercrash oder Timeout,
- Versuch, Sicherheits-, Logging- oder Policyeinstellungen zu ändern,
- unerwartete Persistenz,
- Ausführung aus Temp, Downloads, Cache oder extrahiertem Container.

---

# 8. Was ein reiner Dateiscan nicht erkennen kann

Dateibasierte Analyse muss mit Laufzeitkontrollen kombiniert werden. Nicht zuverlässig allein statisch erkennbar sind:

- ein bisher unbekannter Parser-Zero-Day ohne sichtbare Signatur,
- schädliches Verhalten, das nur unter bestimmten Uhrzeiten, Benutzern, Domains oder Hardwaremerkmalen startet,
- eine legitime Datei, deren externe Ressource später ausgetauscht wird,
- gestohlene, aber formal gültige Signaturen,
- serverseitige zweite Stufen,
- rein soziale Täuschung,
- Model Backdoors ohne geeignete Verhaltenstests,
- Daten, die erst durch einen vorhandenen kompromittierten Prozess interpretiert werden,
- Missbrauch legitimer Funktionen nach Benutzerbestätigung,
- Angriffe durch fehlerhafte Zielanwendung trotz formal valider Datei.

Daraus folgt: **AI Shield braucht statische Analyse, isolierte Detonation, Provenienz und Laufzeit-Consequence-Gates als zusammenhängendes System.**

---

# 9. Architekturvorgabe für AI Shield

## Im Kernel beziehungsweise in treibernahen Komponenten

Nur:

- Create/Open/Execute/Mount/Map/Load beobachten oder blockieren,
- stabile Dateiidentität und Provenienz erfassen,
- Hashing und Gate-Zustand koordinieren,
- Ausführung bis zur Entscheidung verzögern,
- Process-/Image-Load- und Netzwerkfolgen kontrollieren,
- keine komplexen PDF-, Office-, Bild-, Audio-, Video- oder Archivparser.

## Im LocalSystem-Broker

- Policy,
- Orchestrierung,
- Hash-/Provenienzstore,
- Parserpool,
- Quarantäne,
- Audit,
- Entscheidung,
- AppContainer- und Job-Object-Steuerung,
- Signatur- und Trustprüfung.

## In isolierten Parser-Workern

- Formatparser,
- Dekompression,
- Rendering,
- Metadatenextraktion,
- CDR,
- Zielparser-Tests,
- kein dauerhafter privilegierter Zustand,
- kein freier Netzwerkzugriff,
- harte Budgets und Deadline-Termination.

Diese Trennung verhindert, dass gerade die Schutzkomponente durch eine manipulierte Datei zum privilegierten Angriffsziel wird.

---

# 10. Testkorpus und Qualitätssicherung

Für jede Dateifamilie benötigt AI Shield mindestens folgende Testklassen:

1. valide Minimaldatei,
2. valide große Datei,
3. abgeschnittene Datei,
4. falsche Endung,
5. falscher MIME-Typ,
6. Polyglot,
7. trailing data,
8. doppelte Header oder Objekte,
9. ungültige Offsets und Längen,
10. extreme Objektzahl,
11. extreme Rekursion,
12. Kompressionsbombe,
13. verschlüsselter Inhalt,
14. eingebettete ausführbare Datei,
15. externe HTTP-Referenz,
16. UNC-/WebDAV-Referenz,
17. Unicode-/Dateinamenspoofing,
18. Parsercrash-Regression,
19. Timeout-Regression,
20. CDR-Sollvergleich,
21. Signatur gültig/ungültig/abgelaufen/widerrufen,
22. MOTW vorhanden/verloren/vererbt,
23. erlaubtes aktives Dokument,
24. blockiertes aktives Dokument,
25. Laufzeitversuch eines Child Processes,
26. Laufzeitversuch eines Netzwerkzugriffs,
27. Laufzeitversuch einer Persistenzänderung,
28. Quarantäne- und Recovery-Test,
29. Audit- und Causal-Chain-Vollständigkeit,
30. deterministische Wiederholbarkeit.

Für Parser dürfen nur ungefährliche, synthetische Regressionstests und rechtmäßig verfügbare Testkorpora verwendet werden. Produktionssysteme dürfen keine echten Schadproben außerhalb einer isolierten Laborumgebung verarbeiten.

---

# 11. Priorisierte Implementierungsreihenfolge

## Priorität 0 – zwingend vor breitem Dateisupport

- Magic-/MIME-/Extension-Abgleich,
- Provenienz und MOTW-Vererbung,
- rekursive Containeranalyse mit Budgets,
- Polyglot-/Trailing-Data-Erkennung,
- Quarantäne,
- Execute Gate,
- Parserpool im AppContainer,
- Runtime Child-Process-/Network-/Persistence-Gates.

## Priorität 1 – häufigste Angriffswege

- PE und Windows-Installer,
- PowerShell/JS/VBS/BAT/CMD/HTA,
- Office einschließlich VBA, XLM, DDE, OLE, ActiveX und Relationships,
- PDF einschließlich JavaScript, OpenAction, Launch und Attachments,
- ZIP/7z/RAR/CAB/ISO,
- LNK/URL/CHM/OneNote,
- EML/MSG/MIME,
- HTML/MHTML/SVG.

## Priorität 2 – häufig automatisch geparste Inhalte

- JPEG/PNG/GIF/TIFF/WebP/HEIF/AVIF,
- WAV/MP3/FLAC/Ogg/M4A/WMA,
- MP4/MOV/AVI/MKV/WebM,
- Fonts,
- XPS und Druckformate,
- Playlists und Untertitel.

## Priorität 3 – Enterprise- und Entwicklerkontext

- Paketmanager,
- IDE-/Buildprojekte,
- Java/.NET-Pakete,
- Datenbanken,
- Zertifikate und Verbindungsprofile,
- Browser-/IDE-/Office-Plugins,
- KI-/ML-Modellformate.

## Priorität 4 – Spezialdomänen

- CAD/3D/BIM,
- GIS,
- G-Code und Maschinensteuerung,
- Firmware und Geräteupdates,
- Spielemods und anwendungsspezifische Container.

---

# 12. Abschließende Sicherheitsanforderung

AI Shield darf eine Datei niemals allein deshalb als sicher einstufen, weil:

- die Endung bekannt ist,
- der MIME-Typ harmlos aussieht,
- kein klassischer Virensignaturtreffer vorliegt,
- die Datei signiert ist,
- sie sich ohne Absturz öffnen lässt,
- sie aus einem Archiv extrahiert wurde,
- sie von einem bekannten Absender stammt,
- sie keine direkt sichtbare ausführbare Datei enthält,
- ein einzelner Parser sie akzeptiert,
- die Sandbox während eines einzigen kurzen Laufs nichts beobachtet hat.

Die Freigabe muss aus **Identität, Struktur, enthaltenen Fähigkeiten, Provenienz, Vertrauensprüfung, statischer Evidenz, isoliertem Verhalten und Laufzeitfolgen** abgeleitet werden.

---

# Implementiert

Stand: 14. Juli 2026, Release Candidate `2.0.0-rc.12`

Dieser Abschnitt ordnet die in diesem Dokument geforderten Kontrollen dem tatsächlich
implementierten RC12-Stand zu. **Implementiert** bedeutet entweder eine positive technische
Analyse oder eine konservative Fail-closed-Behandlung. Es bedeutet nicht, dass AI Shield jeden
zukünftigen Parserfehler oder jede semantische Manipulation zweifelsfrei erkennen kann.

## 1. Universeller Eingangsfilter

- `include/ai_shield/file_preflight.hpp` und `src/file_preflight.cpp` erkennen PE, PDF, ZIP, WAV,
  PNG, JPEG, GIF, TIFF, WebP, MP4, OLE, RTF und Markup anhand des Inhalts.
- Dateiendung, erkannter Typ und Dateiname werden gegeneinander geprüft. Doppelendungen,
  ausführbare Tarnungen, Bidi-Steuerzeichen, abschließende Punkte/Leerzeichen und überlange Namen
  erzeugen Risikoevidenz.
- Zusätzliche PE-, PDF-, ZIP- und RIFF-Signaturen, PDF-/PNG-Trailing-Data und widersprüchliche
  Containermerkmale werden als Polyglot- oder Einbettungsrisiko behandelt.
- Externe Referenzen, Befehlsindikatoren, automatische Aktionen, aktive Office-/Webinhalte und
  unsichere Serialisierungsformate wie Pickle-, Joblib- und Modell-Checkpoints werden erkannt.
- Unbekannte oder nicht vollständig analysierbare Formate fallen in die eigene Policy-Kategorie
  `unknown` und dürfen die Schutzkette nicht mehr allein wegen einer unbekannten Endung umgehen.

## 2. Formatspezifische Strukturkontrollen

- `src/wav_preflight.cpp` validiert RIFF-/WAVE-Grenzen, Chunkgrößen, `fmt`-/`data`-Konsistenz und
  verdächtige Befehle in Metadaten. Die im Projekt dokumentierte synthetische Trigger-WAV wird
  strukturell blockiert; eine harmlose PCM-WAV bleibt zulässig.
- `src/zip_preflight.cpp` prüft lokale Header, Central Directory, Data Descriptor, ZIP64, CRC-32,
  UTF-8-Namen, Pfadtraversal, Bombenbudgets, Verschlüsselung, nicht unterstützte Kompression,
  ausführbare oder aktive Kinder, verschachtelte Container und doppelte Namen. Stored sowie
  Fixed-/Dynamic-DEFLATE werden rekursiv unter gemeinsamen Tiefen-, Größen- und Eintragslimits
  analysiert.
- PDF-, Bild-, Web-, Dokument-, Archiv-, Audio-, Video-, Programm-, Skript-, Launcher-, Paket- und
  Modellfamilien werden über Content-Policy v4 klassifiziert. Wo kein tiefer Spezialparser besteht,
  greift die Freigabeschranke statt einer stillen Positivfreigabe.

## 3. TOCTOU-feste Analyse und Provenienz

- Der Broker öffnet die Datei einmal, sperrt sie gegen konkurrierendes Umbenennen/Löschen und gibt
  dem Scanner ausschließlich dieses vererbte Handle. Der Scanner öffnet keinen Pfad erneut.
- Größe, Änderungszeit, Volume-/File-ID und ein über dasselbe Handle gestreamter SHA-256-Hash
  binden Klassifizierung, Provenienz und Quarantäneentscheidung an dasselbe Dateiobjekt.
- Bereits bekannte Pfade werden bei Inhaltsänderung erneut geprüft. Vorhandene Dateien werden beim
  Brokerstart als Baseline erfasst; neue oder veränderte Dateien im Downloadordner werden auch ohne
  erhaltenes Mark-of-the-Web verarbeitet.
- Der Minifilter sendet nach Cleanup eine Request-ID-gebundene Filter-Manager-Anfrage mit NT-Pfad,
  Volume- und File-ID. Der Broker bestätigt die Aufnahme in eine begrenzte Warteschlange innerhalb
  von 250 ms; die Inhaltsanalyse läuft auf einem separaten Worker und setzt ihr endgültiges Urteil
  über den geschützten Broker-IOCTL. Bis dahin bleiben Lese-, Vorschau-, Mapping- und
  Ausführungszugriffe auf das betroffene Objekt gesperrt; Timeout, Überlast und
  Kommunikationsfehler bleiben `pending`.

## 4. Isolierter Scanner und Laufzeitgrenzen

- `ai_shield_file_scanner.exe` ist ein dedizierter Minimalworker mit nur `Kernel32` als statischer
  Systemabhängigkeit. Er verarbeitet genau ein Handle mit Einprozess-, 512-MiB- und Zeitlimit.
- Der Start erfolgt primär in einem festen AppContainer. Auf dem qualifizierten Windows-Build, auf
  dem der Loader eigene Minimalprogramme vor `main` mit `0xC0000142` beendet, wird ausschließlich
  auf ein privilegienloses Low-Integrity-Token im identischen Job zurückgefallen. Ein unbeschränkter
  LocalSystem-Parserfallback existiert nicht.
- Der WFP-Treiber blockiert für den Scanner alle ein- und ausgehenden IPv4-/IPv6-Verbindungen
  unabhängig vom normalen Policy-Modus. Ein analysierter Inhalt erhält keinen Netzwerkkanal.
- AMSI wird dynamisch im Worker aufgerufen. Timeout, Startfehler und nicht interpretierbare
  Ergebnisse werden an den Broker zurückgegeben und bei aktivem Fail-closed nicht als sauber
  umgedeutet.

## 5. Policy, UI, Quarantäne und Freigabe

- `AIShieldContentPolicy/4` besitzt elf Kategorien beziehungsweise die Bitmaske `2047`, darunter
  **Unbekannte und Spezialformate**. Versionen 1 bis 3 werden monoton auf v4 migriert.
- `fail_closed=true` und `release_required=true` sind die Referenzkonfiguration. Risiko oder fehlende
  tiefe Analysierbarkeit führen zur Quarantäne beziehungsweise begründungspflichtigen Freigabe.
- Die Private-Desktop-UI stellt die unbekannte Kategorie als eigenen Schalter dar. Provenienz,
  Quarantäne, Audit und kontrollierte Wiederherstellung bleiben über die bestehenden Oberflächen
  und Verwaltungsbefehle nachvollziehbar.

## 6. Nachgewiesene Regressionen

- Release- und Debug-Konfiguration bestehen jeweils 15 von 15 CTest-Zielen.
- Unit-Tests decken die synthetische Trigger-WAV, harmlose PCM-WAV, als JPEG getarnte PE-Datei,
  PDF-/ZIP-Polyglots, Trailing-Data, aktives SVG, externe Referenz, irreführende Dateinamen,
  unsichere Modellserialisierung und harmlosen Text ab.
- Der erhöhte Windows-Downloadtest bestätigt Quarantäne für aktive PDF, WAV ohne MOTW, getarnte PE
  und aktives SVG, die Freigabeschranke für unbekannte Endungen sowie SHA-256-Provenienz.
- WFP, Minifilter und ProcessGuard wurden neu gebaut, testsigniert, installiert und im Zustand
  `RUNNING` geprüft. Broker und Core laufen als automatische Windows-Dienste.

## 7. Bewusst konservativ behandelte Restgrenzen

Noch nicht als semantischer Vollparser implementiert sind unter anderem formatspezifische
CDR-Rekonstruktion für jede Familie, Detonation in jeder realen Zielanwendung, Entschlüsselung
passwortgeschützter Container, Cloud-/Publisher-Reputation, Steganografiebeweis,
ML-Modell-Backdoorbewertung sowie gerätespezifische Firmware-, CAD-, GIS- und CNC-Validierung.
Diese Inhalte werden im RC12 nicht automatisch als sicher behauptet, sondern über die Kategorie
für unbekannte oder spezialisierte Formate blockiert beziehungsweise freigabepflichtig behandelt.
