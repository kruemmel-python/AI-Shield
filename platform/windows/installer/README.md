# Windows Installer

Reserved for system preflight, driver package installation, protected-service setup and recovery wiring.

Current prototype installation assets:

- `ai_shield_wfp.inf`
- `ai_shield_minifilter.inf`
- `ai_shield_process_guard.inf`
- `install_drivers.ps1`
- `uninstall_drivers.ps1`
- `update_and_install_drivers.ps1`
- `install_broker.ps1`

The executable `ai_shield_driverctl.exe` installs driver services through the Windows Service Control
Manager. Installation and start/stop operations require an elevated PowerShell session.
Prototype driver signing and activation:

```powershell
powershell -ExecutionPolicy Bypass -File platform\windows\build_drivers.ps1 -Configuration Release
Start-Process powershell -Verb RunAs
Set-Location D:\AI_Shield
powershell -ExecutionPolicy Bypass -File platform\windows\installer\enable_testsigning.ps1 -State on
powershell -ExecutionPolicy Bypass -File platform\windows\installer\sign_driver_package.ps1 -PackageDir driver_package\Release
Restart-Computer
```

If Secure Boot is enabled, Windows protects the `TESTSIGNING` boot option and will later reject these
locally signed drivers with service error `577`. For prototype testing, disable Secure Boot in UEFI
firmware, enable test-signing again, and reboot before loading the drivers.

After reboot, install and start the prototype drivers from an elevated PowerShell:

```powershell
Set-Location D:\AI_Shield
powershell -ExecutionPolicy Bypass -File platform\windows\installer\install_drivers.ps1 -PackageDir D:\AI_Shield\driver_package\Release
build_vs\Release\ai_shield_driverctl.exe status
```

For a rebuilt package, the supported update path stops the broker and drivers, rebuilds, signs,
installs and restarts the complete kernel telemetry stack:

```powershell
powershell -ExecutionPolicy Bypass `
  -File platform\windows\installer\update_and_install_drivers.ps1 `
  -Configuration Release
```

The installed drivers use `SYSTEM_START`. `AIShieldBroker` uses delayed automatic start and depends
on all three drivers. Its data directories are restricted to `SYSTEM` and built-in administrators.
Signed runtime policy is managed separately by
`platform\windows\policy\ai_shield_policy.ps1`.

Stop and remove:

```powershell
powershell -ExecutionPolicy Bypass -File platform\windows\installer\uninstall_drivers.ps1
```
