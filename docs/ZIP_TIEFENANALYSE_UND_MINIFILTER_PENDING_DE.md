# ZIP-Tiefenanalyse und latenzbegrenztes Minifilter-Pending

Stand: 15. Juli 2026, Release Candidate `2.0.0-rc.13`

## Zweck

Diese Schutzstufe verhindert, dass eine neu geschriebene externe Datei zwischen Downloadende und
periodischer Brokerprüfung gelesen, als Vorschau geladen, in einen Prozess gemappt oder ausgeführt
wird. Gleichzeitig werden ZIP-Container nicht nur anhand ihrer Metadaten bewertet, sondern ihre
unterstützten Inhalte rekursiv unter festen Ressourcenbudgets analysiert.

## Latenzbegrenztes Dateiprotokoll

1. Der Minifilter erkennt einen externen Schreibvorgang und markiert Volume-/File-ID als `pending`.
2. Beim Cleanup erzeugt er eine eindeutige Request-ID und ermittelt den normalisierten NT-Pfad.
3. Die Anfrage läuft über `\AIShieldMinifilterPort`. Nur der zuvor registrierte Brokerprozess darf
   sich verbinden; Filter Manager akzeptiert höchstens einen Client.
4. Der Empfangsthread validiert die Anfrage, stellt sie in eine begrenzte Warteschlange und
   bestätigt innerhalb von 250 ms ausschließlich den Zustand `pending`.
5. Ein separater Analyse-Worker öffnet den Pfad mit `FILE_FLAG_OPEN_REPARSE_POINT`, prüft
   Volume-/File-ID, Größe, Änderungszeit, Linkanzahl und Alternate Data Streams und analysiert das
   gesperrte Handle.
6. Das endgültige Urteil wird über den nur für den registrierten Broker erlaubten IOCTL gesetzt.
   Nur `clean` entfernt den Pending-Eintrag; `quarantined` bleibt gesperrt.

Für die reine Kernel-/Broker-Übergabe gilt eine Deadline von 250 ms; Inhaltsanalyse findet nie auf
dem Kernel-I/O-Pfad statt. Portausfall, Timeout, Entladen des Filters, Warteschlangenüberlauf,
Identitätswechsel, fehlerhafte Antwort oder Scannerfehler führen nicht zu einer automatischen
Freigabe. Normale Dateien in `%LOCALAPPDATA%\Temp` werden nicht pauschal gegated. Die periodische
Verzeichnisprüfung bleibt als serialisierter Recovery-Pfad erhalten.

## ZIP- und ZIP64-Prüfung

Der Parser validiert:

- End of Central Directory und ZIP64 EOCD/Locator;
- Central Directory gegen lokale Header;
- optionale 32-/64-Bit-Data-Descriptoren;
- Dateinamen, UTF-8, Pfadtraversal, ADS und doppelte kanonische Namen;
- CRC-32, Nutzdatengrenzen und Überlappung mit dem Central Directory;
- Stored sowie raw DEFLATE mit festen und dynamischen Huffman-Tabellen;
- rekursive ZIP-, JAR-, Office-, OpenDocument- und weitere ZIP-basierte Container.

Ein gemeinsames Budget begrenzt standardmäßig 10.000 Einträge, sechs Rekursionsebenen, 128 MiB pro
Eintrag, 512 MiB expandierte Gesamtdaten und ein Kompressionsverhältnis von 200:1. Die Grenzen
gelten über die gesamte Verschachtelung und können nicht pro Kindarchiv neu begonnen werden.

Verschlüsselte Einträge, unbekannte Kompressionsmethoden, ungültige Huffman-Tabellen, CRC-Fehler,
Headerabweichungen und Budgetüberschreitungen werden fail-closed behandelt. Das System versucht
nicht, Passwörter zu umgehen oder fremde System-DLLs als unkontrollierten Dekompressor zu laden.

## Tests

Die Unit-Tests enthalten Stored, Fixed-DEFLATE, Dynamic-DEFLATE, Data Descriptor, ZIP64,
verschachtelte Archive, Tiefenüberschreitung, CRC-/Header-Manipulation, Pfadflucht,
Kompressionsbomben und überlappende Strukturen. Release und Debug müssen jeweils alle 16 CTest-
Ziele bestehen; der Minifilter wird mit WDK `/W4 /WX` gebaut.

## Betrieb

Die Funktion wird erst nach Installation des RC12-Minifilters und RC12-Brokers wirksam. Ein neuer
Broker mit altem Treiber besitzt keinen Kommunikationsport; ein neuer Treiber ohne laufenden Broker
lässt Dateien absichtlich `pending`. Nach einem Update müssen daher beide Komponenten gemeinsam
installiert und ihr Dienststatus geprüft werden.
