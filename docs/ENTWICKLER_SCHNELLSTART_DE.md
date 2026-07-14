# AI Shield Entwickler-Schnellstart

Stand: 13. Juli 2026, interner ABI-Stand 2.0, Kernel-Transport ABI 1.2

## 1. Inhalt des Entwicklerpakets

Das ZIP enthält den vollständigen C++23-Shared-Core, Windows-Adapter, drei WDK-Treiberprojekte,
INF-Vorlagen, Installer- und Qualifikationsskripte, Tests sowie Projektdokumentation. Lokale
Buildausgaben, Testzertifikate, signierte Binärdateien, Laufzeitdaten und private Schlüssel sind
bewusst nicht enthalten. Jedes Team erzeugt diese Artefakte in seiner eigenen Buildumgebung.

## 2. Voraussetzungen

- Windows 10 oder 11 x64
- Visual Studio 2022 Build Tools mit Desktopentwicklung für C++
- CMake, Windows SDK und WDK 10.0.26100 oder kompatibel
- PowerShell 5.1 oder PowerShell 7
- Administratorrechte nur für Treibersignierung, Installation und Dienststeuerung

Für reine Core- und User-Mode-Entwicklung müssen Secure Boot und die Windows-Bootkonfiguration
nicht geändert werden. Nur lokale, selbstsignierte Kernel-Treibertests benötigen auf dem
Testsystem deaktiviertes Secure Boot, aktiviertes `TESTSIGNING` und einen Neustart. Produktive
Rechner dürfen dafür nicht verwendet werden.

## 3. User-Mode bauen und testen

Im entpackten Projektverzeichnis:

```powershell
$CMAKE_EXE = "C:\Program Files\CMake\bin\cmake.exe"
$CTEST_EXE = "C:\Program Files\CMake\bin\ctest.exe"
& $CMAKE_EXE -S . -B build_vs -G "Visual Studio 17 2022" -A x64 `
  -DAI_SHIELD_ENABLE_WINDOWS_PLATFORM=ON
& $CMAKE_EXE --build build_vs --config Release --parallel
& $CTEST_EXE --test-dir build_vs -C Release --output-on-failure
```

Der aktuelle Stand besitzt zwölf CTest-Ziele. Danach kann der gefahrlose Demo-Modus ohne Treiber
gestartet werden:

```powershell
build_vs\Release\ai_shield_prototype.exe --listen 127.0.0.1:18080 --demo
```

In einem zweiten Fenster:

```powershell
curl.exe http://127.0.0.1:18080/safe
curl.exe --path-as-is http://127.0.0.1:18080/../../secret
```

Die erste Anfrage wird erlaubt, die zweite mit `request_not_processed` blockiert.

## 4. Lokales Backend schützen

```powershell
New-Item -ItemType Directory -Force test_backend | Out-Null
Set-Content test_backend\index.html "<h1>AI Shield Backend aktiv</h1>"
python -m http.server 18081 --bind 127.0.0.1 --directory .\test_backend
```

Gateway in einem zweiten Fenster:

```powershell
build_vs\Release\ai_shield_prototype.exe `
  --listen 127.0.0.1:18080 --backend 127.0.0.1:18081
```

## 5. Treiber bauen und lokal testen

Auf einer isolierten Testmaschine oder VM in einer administrativen PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File platform\windows\build_drivers.ps1 -Configuration Release
powershell -ExecutionPolicy Bypass -File platform\windows\installer\enable_testsigning.ps1 -State on
Restart-Computer
```

Wenn Windows meldet, dass die BCD-Option durch Secure Boot geschützt ist, muss Secure Boot zuvor
in der UEFI-Konfiguration des Testsystems deaktiviert werden. Danach signieren und installieren:

```powershell
powershell -ExecutionPolicy Bypass -File platform\windows\installer\sign_driver_package.ps1 `
  -PackageDir "$PWD\driver_package\Release"
powershell -ExecutionPolicy Bypass -File platform\windows\installer\install_drivers.ps1 `
  -PackageDir "$PWD\driver_package\Release"
build_vs\Release\ai_shield_driverctl.exe status
```

Erwartet wird für alle drei Treiber `state=4 win32_exit=0`. Fehler 577 bedeutet eine nicht von der
aktuellen Bootrichtlinie akzeptierte Signatur.

## 6. Komponenten starten

Der Demo-Einstieg ist `AI_Shield_Start_Demo.cmd`. Der Backend-Einstieg ist
`AI_Shield_Start.cmd`. Die Skripte erwarten die Release-Ausgaben unter `build_vs\Release`.
Der LocalSystem-Broker wird durch den Installer eingerichtet und liest Kernel-ABI 1.2, übersetzt
es an der Vertrauensgrenze auf ABI 2.0 und authentisiert interne Ereignisse mit HMAC-SHA-256.
`install_core_service.ps1` installiert zusätzlich den Watchdog `AIShieldCore`.

## 7. Entwicklungsregeln

- Windows-Typen bleiben in `platform/windows`; `include/ai_shield` und `src` bleiben portabel.
- ABI-Strukturgrößen und Offsets dürfen nicht ohne Major-Version geändert werden.
- Tests müssen in Debug und Release wirksam sein und dürfen nicht von C-Assertions abhängen.
- Treiberenforcement benötigt immer eine signierte, monotone Policy und einen Recovery-Pfad.
- Kein Testzertifikat oder privater Schlüssel wird in Quellpakete eingecheckt oder verteilt.

Bekannte Restarbeiten und externe Release-Gates stehen in
[`FEHLENDE_FUNKTIONEN_DE.md`](FEHLENDE_FUNKTIONEN_DE.md).

Die getrennten Paket- und Bedienpfade sind in
[`EDITIONEN_UND_VERSIONEN_DE.md`](EDITIONEN_UND_VERSIONEN_DE.md),
[`PRIVATE_DESKTOP_HANDBUCH_DE.md`](PRIVATE_DESKTOP_HANDBUCH_DE.md) und
[`DEVELOPER_FULL_HANDBUCH_DE.md`](DEVELOPER_FULL_HANDBUCH_DE.md) beschrieben.
