# AI Shield Developer Full Handbuch

Stand: 14. Juli 2026

## Paketinhalt

`AI_Shield_Developer_Full.zip` enthält den vollständigen C++23-Quellstand, CMake-Projekt, Tests,
Windows-Adapter, drei WDK-Treiberprojekte, INF-Vorlagen, Installer-, Qualifikations- und
Paketierungsskripte, diese Dokumentation sowie eine vorkompilierte Private-Desktop-Referenz.
Private Signierschlüssel, PFX/PVK-Dateien, Maschinenzustand und Laufzeitaudits gehören nicht in das
Entwicklerpaket.

## Voraussetzungen

- Windows 10/11 x64;
- Visual Studio 2022 mit Desktopentwicklung für C++;
- CMake unter `C:\Program Files\CMake\bin`;
- kompatibles Windows SDK und WDK;
- PowerShell 5.1 oder PowerShell 7.

## Bauen und testen

```powershell
$cmake = "C:\Program Files\CMake\bin\cmake.exe"
$ctest = "C:\Program Files\CMake\bin\ctest.exe"
& $cmake -S . -B build_vs -G "Visual Studio 17 2022" -A x64 `
  -DAI_SHIELD_ENABLE_WINDOWS_PLATFORM=ON
& $cmake --build build_vs --config Release --parallel
& $ctest --test-dir build_vs -C Release --output-on-failure
powershell -ExecutionPolicy Bypass -File platform\windows\build_drivers.ps1 `
  -Configuration Release -PackageDirectory driver_package\Release -Rebuild
```

Der aktuelle Stand besitzt 14 CTest-Ziele. Die zusätzlichen Gates prüfen Tray-Autostart,
UI-Einzelinstanz und Close-to-Tray. Das Recovery-Gate prüft den Vault einschließlich
Snapshot, Erkennung, Restore, externem Backup und einem nicht auflösbaren Junction-Ziel. Release-Tests verwenden eine eigene wirksame
Testprüfung und dürfen sich nicht auf durch `NDEBUG` entfernte C-Assertions verlassen.

## Treiberlabor

Für das reine Bauen sind keine Bootänderungen nötig. Nur das Laden lokal testsignierter Treiber
erfordert auf einer isolierten Testmaschine deaktiviertes Secure Boot, aktiviertes `TESTSIGNING`
und einen Neustart. Fehler `577` bedeutet, dass Windows die Treibersignatur unter der aktuellen
Bootrichtlinie nicht akzeptiert.

```powershell
powershell -ExecutionPolicy Bypass -File platform\windows\installer\sign_driver_package.ps1 `
  -PackageDir "$PWD\driver_package\Release"
powershell -ExecutionPolicy Bypass -File platform\windows\installer\install_drivers.ps1 `
  -PackageDir "$PWD\driver_package\Release"
build_vs\Release\ai_shield_driverctl.exe status
```

Erwartet wird für WFP, MiniFilter und ProcessGuard `state=4 win32_exit=0`.

## Referenzinstallation und Pakete

Die vorkompilierte Referenz kann über `prebuilt\AI_Shield_Private_Desktop.msi` oder den vorhandenen
Developer-Full-Installationsstarter installiert werden. Vor einer Weitergabe müssen Paketmanifest,
SHA-256-Werte, CTest, UI-Vertrag und Treibersignaturen erneut geprüft werden. Das Entwicklerpaket
selbst ist keine Microsoft-signierte Produktionsdistribution.

Weitere Details: [Entwickler-Schnellstart](ENTWICKLER_SCHNELLSTART_DE.md),
[ABI Freeze/HLK](ABI_FREEZE_UND_HLK_DE.md) und
[Produktqualifikation](PRODUKTQUALIFIKATION_DE.md). Der zuletzt verifizierte Referenzlauf ist im
[RC10 Release- und Installationsnachweis](RC10_RELEASE_NACHWEIS_DE.md) dokumentiert. Die
[RC9-](RC9_RELEASE_NACHWEIS_DE.md) und [RC8-Nachweise](RC8_RELEASE_NACHWEIS_DE.md) bleiben als
historische Baselines erhalten.
