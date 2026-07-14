# AI Shield ABI 2.0

Stand: 14. Juli 2026

## Geltungsbereich

ABI 2.0 ist der interne, plattformneutrale Ereignisvertrag zwischen Windows-Adaptern,
Broker und Shared Core. Das eingefrorene Kernel-IOCTL-Protokoll bleibt an der
Treibergrenze kompatibel zu `AIShieldDriverABI/1.2` (Freeze-Revision `2`). Der Windows-Adapter validiert jede
72-Byte-Treiberstruktur und übersetzt sie unmittelbar in ABI 2.0. Unvalidierte Kernelbytes
gelangen nicht in Audit, Korrelation oder Policy-Auswertung.

## Eingefrorene Strukturen

| Struktur | Größe | Zweck |
|---|---:|---|
| `MessageHeader` | 104 Byte | Version, Typ, Größe, Sequenz, Zeit, Objekt-, Policy- und Modellbezug, MAC |
| `SensorEvent` | 248 Byte | Sensorereignis mit Prozess-, Provenance-, Netzwerk- und Evidenzfeldern |

Die Definitionen liegen in `include/ai_shield/abi2.hpp`. Beide Strukturen sind Standard
Layout, trivial kopierbar und über Compile-Time-Prüfungen auf Größe und kritische Offsets
eingefroren. Mehrbytewerte sind innerhalb des aktuellen x64-Vertrags little-endian. Neue
inkompatible Felder erfordern eine neue Major-Version; kompatible Erweiterungen benötigen
eine Minor-Version und eine explizite Größenregel.

## Integrität und Ablehnung

Jede Nachricht wird deterministisch serialisiert und mit HMAC-SHA-256 authentisiert. Der lokale
Broker erzeugt den 256-Bit-Kanalschlüssel über den Windows-CNG-Systemgenerator. Schlüssel,
Generation, Policy- und Modellversion liegen DPAPI-Machine-geschützt in `runtime-state.dpapi` und
`runtime-state.recovery.dpapi`. Eine vorhandene rohe `channel.key` wird einmalig migriert und
anschließend entfernt. Rotation hält genau eine Recovery-Generation vor.

Vor Annahme werden Magic, Major/Minor, Nachrichtentyp, Header- und Gesamtgröße,
Payloadgröße, bekannte Flags, exakte Sequenz, monotone Zeit und MAC geprüft. Unbekannte
oder veränderte Nachrichten werden fail-closed verworfen. Das Audit übernimmt nur validierte
ABI-2.0-Ereignisse. `AISHAD02` speichert Flow-, Objekt-, Datei-, Volume-, Provenance-, Prozess-,
Parent-, Policy- und Modellbezug. Andere Auditformatversionen werden fail-closed abgelehnt.

## Sandbox-Grenze

Der AppContainer-Launcher startet Parser weiterhin suspendiert und weist sie vor der
Freigabe einem Job Object zu. Das Job Object erzwingt Prozessspeicher- und Prozessanzahl-
Grenzen, beendet alle Worker beim Schließen und beendet Prozesse nach unbehandelten
Fehlern. Netzwerk- und Kindprozessfreigaben werden in Tier 1 abgelehnt. Erst
`resume_launched_process` gibt einen erfolgreich isolierten Worker frei.

## Verifikation

Der saubere Release-Build `build_vs_abi2` kompiliert Core, Windows-Adapter, Broker und
Werkzeuge. Die 14 CTest-Ziele prüfen unter anderem ABI-HMAC-Manipulation, ABI-1.2-zu-2.0-
Übersetzung, Plattformadapter und die ausführbaren Self-Tests.

Nicht Teil dieses Meilensteins sind Hyper-V-Tier-2, Sovereign Mode, Microsoft-HLK-Ausführung,
Microsoft-Produktionssignierung und mehrmonatige Neustart-/Soak-Nachweise. Diese Punkte
können nicht durch lokalen Quellcode ersetzt werden und bleiben externe Release-Gates.
