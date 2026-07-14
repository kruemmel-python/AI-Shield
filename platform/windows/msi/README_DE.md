# MSI-Installer fuer AI Shield Private Desktop

Der x64-MSI installiert die vollständige Private-Desktop-Ausgabe pro Computer nach
`C:\Program Files\AI_Shield_Private_Desktop`. Er registriert das Produkt in Windows, unterstützt
Major Upgrades und ruft die vorhandene erhöhte Produktinstallation auf. Dadurch werden zusätzlich
zu den Paketdateien folgende Windows-Ressourcen verwaltet:

- `AIShieldWfp`, `AIShieldMiniFilter` und `AIShieldProcessGuard` einschließlich SYS/INF-Paket;
- `AIShieldBroker` und `AIShieldCore` einschließlich Wiederanlaufkonfiguration;
- Browser-Native-Messaging-Host, lokale Policy sowie transaktionale Firewall-/Defender-Baselines;
- Startmenüeintrag und grafische Private-Desktop-Oberfläche.

## Bauen

Voraussetzungen sind das fertige `AI_Shield_Private_Desktop.zip`, WiX Toolset 3.14 und das Windows
SDK. Der normale Build signiert die MSI mit dem lokalen AI-Shield-Testzertifikat:

```powershell
Set-Location D:\AI_Shield
powershell -ExecutionPolicy Bypass -File platform\windows\msi\build_msi.ps1
```

Nur für einen internen, nicht verteilbaren Build kann `-SkipSigning` verwendet werden. Ausgabe:
`dist\msi\AI_Shield_Private_Desktop_2.0.0-rc.12_x64.msi` plus SHA-256-Datei.

## Installieren und deinstallieren

Die grafische Installation erfolgt per Doppelklick und UAC-Bestätigung. Für reproduzierbare Logs:

```powershell
msiexec.exe /i .\dist\msi\AI_Shield_Private_Desktop.msi /l*v .\runtime\msi-install.log
msiexec.exe /x .\dist\msi\AI_Shield_Private_Desktop.msi /l*v .\runtime\msi-uninstall.log
```

Der qualifizierte Upgradepfad stoppt Broker/Core, entfernt die alten Treiberdienste und startet
danach das MSI mit ausführlichem Log:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File tools\install_private_desktop_release.ps1 `
  -MsiPath dist\msi\AI_Shield_Private_Desktop_2.0.0-rc.12_x64.msi
```

Eine stille Installation nutzt `/qn`. Die Deinstallation stoppt und entfernt beide Dienste und alle
drei Treiber, deregistriert den Browser-Host und rollt nur von dieser Installation angelegte
Baselines zurück. Audit-, Incident- und Quarantänedaten bleiben als Sicherheitsnachweis erhalten.
Der technische Aktionslog liegt unter
`C:\ProgramData\AIShield\installer\msi-product-action.log`.

Die lokal testsignierten Treiber benötigen weiterhin deaktiviertes Secure Boot, aktiviertes
`TESTSIGNING` und einen Neustart. Ein MSI kann diese Windows-Vertrauensgrenze weder seriös noch
sicher umgehen. Für einen öffentlichen Installer muss derselbe MSI-Build mit Microsoft-signierten
Treibern und einem vertrauenswürdigen Publisher-Zertifikat erzeugt werden.
