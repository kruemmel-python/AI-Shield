# AI Shield: ABI Freeze und HLK-Übergabe

Stand: 15. Juli 2026, Kernel-Transport ABI `1.2`, Freeze-Revision `3`

## Eingefrorenes ABI

Das Treiberprotokoll ist als `AIShieldDriverABI/1.2` eingefroren:

```text
protocol_version = 0x00010002
freeze_revision = 3
packing = 8
AI_SHIELD_DRIVER_POLICY = 32 Bytes
AI_SHIELD_DRIVER_STATUS = 56 Bytes
AI_SHIELD_DRIVER_EVENT = 72 Bytes
schema_sha256 = 8152bb2807a796ae7f5bd234edfb11624ffb07ac263b2eb69a83b02c97d06a65
```

`ai_shield_driver_protocol.h` enthält Compile-Time-Prüfungen für Größen und sicherheitsrelevante
Offsets. Dieselben Invarianten werden vom C++-Build, von allen WDK-C-Treibern und durch
`validate_abi_freeze.ps1` geprüft. Eine inkompatible Änderung benötigt künftig eine neue
Protokollversion, Freeze-Revision, Schemazeichenfolge und Migrationslogik. Bestehende Felder dürfen
nicht umgedeutet werden.

```powershell
powershell -ExecutionPolicy Bypass `
  -File platform\windows\verification\validate_abi_freeze.ps1
```

Das Microsoft-Submission-Verzeichnis enthält `ABI_MANIFEST.json` neben CAB und Hashmanifest.

## HLK-Laborübergabe

Auf dem aktuellen Entwicklungsrechner ist das WDK installiert, aber kein HLK Controller oder HLK
Studio. Deshalb können hier keine WHCP-/HLK-Playlists ausgeführt oder `.hlkx`-Ergebnisse erzeugt
werden. Das Readiness-Gate dokumentiert diesen Zustand maschinenlesbar:

```powershell
powershell -ExecutionPolicy Bypass `
  -File platform\windows\verification\prepare_hlk_lab.ps1 `
  -Controller <HLK-CONTROLLER> -RequireInstalledHlk
```

Im Labor müssen die Pakete als Softwaregeräte beziehungsweise Treiberziele installiert, im HLK
Controller erkannt und alle vom aktuellen HLK für Zielklasse und Betriebssystem ermittelten Tests
ausgeführt werden. Die Auswahl aus HLK Studio ist maßgeblich; eine statische, veraltbare Namensliste
im Repository darf sie nicht ersetzen. Schwerpunkte sind Netzwerkfilter, Dateisystemfilter,
Kernel-Treiber, Code Integrity, Driver Verifier und Zuverlässigkeit.

Erst nach grünen Playlists wird das HLK-Paket mit der Organisationsidentität signiert und im
Hardware Dashboard eingereicht. Das von Microsoft zurückgegebene Paket muss anschließend mit
`verify_microsoft_signed_package.ps1` geprüft und unter aktivem Secure Boot erneut durch Install-,
Reboot-, HVCI-, Last- und Recovery-Gates geführt werden.
