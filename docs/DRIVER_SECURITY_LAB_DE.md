# AI Shield: HVCI- und Driver-Verifier-Labor

Stand: 14. Juli 2026

Diese Prüfungen können einen Testrechner unbootbar machen oder absichtlich einen Bugcheck auslösen.
Sie dürfen nur auf einem wiederherstellbaren Laborrechner oder VM-Snapshot ausgeführt werden.

Nur Status erfassen:

```powershell
powershell -ExecutionPolicy Bypass `
  -File platform\windows\verification\driver_security_lab.ps1 `
  -Action preflight
```

Driver Verifier ausschließlich für die drei AI-Shield-Treiber aktivieren:

```powershell
powershell -ExecutionPolicy Bypass `
  -File platform\windows\verification\driver_security_lab.ps1 `
  -Action arm-verifier -ConfirmSystemChange
Restart-Computer
```

Notfall-Reset aus einer administrativen Konsole oder Wiederherstellungsumgebung:

```powershell
verifier.exe /reset
Restart-Computer
```

HVCI ohne permanenten UEFI-Lock für einen reversiblen Labortest anfordern:

```powershell
powershell -ExecutionPolicy Bypass `
  -File platform\windows\verification\driver_security_lab.ps1 `
  -Action arm-hvci -ConfirmSystemChange
Restart-Computer
```

Nach jedem Neustart müssen `driver_security_lab.ps1 -Action status`, die Reboot-Qualifikation und
mindestens der Recovery-/Lastlauf ausgeführt werden. Die lokale Testsigning-Konfiguration mit
deaktiviertem Secure Boot ist kein Nachweis für Produktions-HVCI. Der verbindliche Gate muss mit
dem später von Microsoft signierten Rückpaket und aktiviertem Secure Boot wiederholt werden.
