# AI Shield Developer Full

Dieses Paket kombiniert zwei getrennte Arbeitsabläufe:

1. **Quellcode bauen und testen:** `Build_All_Release.cmd` erzeugt den x64-Release-Build, führt alle
   CTest-Ziele aus und baut anschließend die drei Windows-Treiber mit dem WDK.
2. **Geprüfte Referenzversion installieren:** `Install_Precompiled_Desktop.cmd` entpackt das
   enthaltene Consumer-Paket nach `C:\Program Files\AI_Shield_Private_Desktop` und startet dessen
   Installer.

Die Desktop-Referenz enthält außerdem den signierten Native-Messaging-Host und die lokal ladbare
Manifest-V3-Erweiterung für Microsoft Edge und Google Chrome.

## Buildvoraussetzungen

- Windows 10/11 x64;
- Visual Studio 2022 mit C++-Desktopworkload;
- CMake unter `C:\Program Files\CMake\bin`;
- Windows SDK und Windows Driver Kit (WDK);
- PowerShell 5.1 oder neuer.

Der Build benötigt kein deaktiviertes Secure Boot. Das Laden lokal testsignierter Treiber dagegen
schon. Die vorkompilierte Referenzversion kann nur als Administrator und nur mit deaktiviertem
Secure Boot sowie aktiviertem `TESTSIGNING` installiert werden. Diese Einschränkung endet erst mit
einer Microsoft-Produktionssignatur.

## Neu bauen

```powershell
.\Build_All_Release.cmd
```

Der Ablauf entspricht:

```powershell
$cmake = "C:\Program Files\CMake\bin\cmake.exe"
$ctest = "C:\Program Files\CMake\bin\ctest.exe"
& $cmake -S . -B build_vs -G "Visual Studio 17 2022" -A x64
& $cmake --build build_vs --config Release --parallel
& $ctest --test-dir build_vs -C Release --output-on-failure
powershell -File platform\windows\build_drivers.ps1 -Configuration Release `
  -PackageDirectory driver_package\Release -Rebuild
```

Selbst gebaute Treiber sind zunächst nicht produktionssigniert. Für Laborzwecke müssen sie mit dem
lokalen Testzertifikat signiert werden. Das enthaltene vorkompilierte Consumer-Paket besitzt bereits
die für den Prototyp notwendigen Testsignaturen; ein privater Signierschlüssel ist nicht enthalten.

## Vorkompilierte Version installieren

Bevorzugt die signierte MSI per Doppelklick und UAC-Bestätigung installieren:

```powershell
msiexec.exe /i .\prebuilt\AI_Shield_Private_Desktop.msi /l*v .\msi-install.log
```

Sie erscheint anschließend unter **Installierte Apps** und entfernt bei der Deinstallation auch
Broker, Core und alle drei Treiber. Audit- und Quarantänedaten bleiben standardmäßig erhalten.
Der bisherige ZIP-Referenzpfad bleibt für Entwicklungstests verfügbar:

```powershell
.\Install_Precompiled_Desktop.cmd
```

Der Installer prüft den Hash des eingebetteten Consumer-ZIP gegen `FULL_PACKAGE_MANIFEST.json`,
entpackt es in einen stabilen Program-Files-Ordner und installiert Treiber, Broker, Core, Policy,
Windows-Baselines, Startmenüeintrag und WPF-Oberfläche.

## Paketstruktur

- `include`, `src`, `kernel`, `platform`, `tools`, `tests`: vollständiger Entwicklungsstand;
- `docs`, `editions`: Dokumentation und Private-Desktop-Edition;
- `prebuilt\AI_Shield_Private_Desktop.zip`: installierbare Referenzversion;
- `prebuilt\AI_Shield_Private_Desktop.msi`: per-machine x64-Installer mit vollständigem Rückbau;
- `FULL_PACKAGE_MANIFEST.json`: SHA-256 aller ausgelieferten Dateien.

Lokale Zertifikat-Private-Keys, PFX/PVK-Dateien, Buildverzeichnisse, Laufzeitprotokolle und
Maschinenzustände werden nicht ausgeliefert.
