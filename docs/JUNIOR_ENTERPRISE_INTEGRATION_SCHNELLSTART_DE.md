# AI Shield: Junior-Schnellstart fuer externe Integrationen

Stand: 13. Juli 2026

## Ziel und Sicherheitsregel

Diese Anleitung verbindet drei bereits implementierte AI-Shield-Komponenten mit realen externen
Systemen:

1. verwaltete Chrome-/Edge-Erweiterung,
2. Windows Event Collector ueber HTTPS,
3. HTTPS-Endpunkt fuer datensparsame PowerShell-Ereignisse.

Eine URL, Extension-ID oder ein Zertifikatpin darf niemals erfunden oder aus dieser Anleitung
uebernommen werden. Verwende ausschliesslich Werte des tatsaechlich administrierten Zielsystems.
Arbeite zuerst in einer Test-VM. Halte die jeweilige Rollback-Konsole geoeffnet.

## Begriffe

- **Extension-ID:** 32 Zeichen aus `a` bis `p`, die Chrome oder Edge einer veroeffentlichten oder
  kryptografisch gepackten Erweiterung zuweist.
- **Update-URL:** HTTPS-Adresse, unter der der Browser das Update-Manifest der Erweiterung abruft.
- **Zertifikatpin:** SHA-256-Fingerabdruck des aktuell erwarteten Serverzertifikats, 64 Hexzeichen.
- **WEF/WEC:** Windows Event Forwarding sendet Ereignisse an einen Windows Event Collector.
- **Rollback:** Wiederherstellung des Zustands vor der Konfiguration.

## Allgemeine Vorbereitung

1. Oeffne Windows PowerShell 5.1 als Administrator.
2. Wechsle in das Projekt:

```powershell
Set-Location D:\AI_Shield
```

3. Baue und teste den aktuellen Stand:

```powershell
$cmake = "C:\Program Files\CMake\bin\cmake.exe"
$ctest = "C:\Program Files\CMake\bin\ctest.exe"
& $cmake -S . -B build_vs -G "Visual Studio 17 2022" -A x64
& $cmake --build build_vs --config Release --parallel
& $ctest --test-dir build_vs -C Release --output-on-failure
```

Erwartet werden elf bestandene Tests. Fahre bei einem Fehler nicht mit der Installation fort.

## Teil A: Browser-Erweiterung

### A.1 Was ein Administrator bereitstellen muss

Der Quellcode liegt unter `platform\windows\browser_extension`. Fuer einen verwalteten Rollout muss
ein Browser-/Endpoint-Administrator die Erweiterung in einem kontrollierten Extension-Store
veroeffentlichen oder als intern verwaltetes Paket bereitstellen. Von ihm benoetigst du:

- die reale Extension-ID,
- die HTTPS-Update-URL,
- die Bestaetigung, dass Chrome und/oder Edge diese URL erreichen duerfen.

Eine lokal mit „Entpackte Erweiterung laden“ gestartete Erweiterung ist fuer einen produktiven
Rollout nicht ausreichend. Ihre ID kann sich ohne stabilen kryptografischen Schluessel aendern.

### A.2 Native Host bauen und signieren

```powershell
& $cmake --build build_vs --config Release --target ai_shield_browser_host
powershell -ExecutionPolicy Bypass `
  -File platform\windows\browser_extension\sign_browser_host.ps1
```

Pruefe die Signatur:

```powershell
$signature = Get-AuthenticodeSignature `
  D:\AI_Shield\build_vs\Release\ai_shield_browser_host.exe
$signature.Status
$signature.SignerCertificate.Thumbprint
```

`Status` muss `Valid` sein. Der aktuelle lokale Prototyp-Publisher besitzt auf diesem Testsystem den
Thumbprint `125D756E7666534CDF4558A2B9E96E96907B3FFC`. In Produktion muss hier das echte
Unternehmenszertifikat stehen.

### A.3 Installation

Ersetze alle Werte in spitzen Klammern:

```powershell
$extensionId = "<REALE_32_ZEICHEN_EXTENSION_ID>"
$updateUrl = "https://<VERWALTETER-SERVER>/extensions/update.xml"
$publisher = "<REALE_40_ZEICHEN_PUBLISHER_THUMBPRINT>"

powershell -ExecutionPolicy Bypass `
  -File platform\windows\browser_extension\install_browser_sensor.ps1 `
  -ExtensionId $extensionId `
  -PublisherThumbprint $publisher `
  -UpdateUrl $updateUrl `
  -ConfirmSystemChange
```

Der Installer bricht ab, wenn Signatur, Publisher-Pin, ID oder HTTPS-URL nicht passen.

### A.4 Erfolg pruefen

```powershell
Get-AuthenticodeSignature `
  "C:\Program Files\AIShield\browser\ai_shield_browser_host.exe"

Get-ItemProperty `
  "HKLM:\SOFTWARE\Google\Chrome\NativeMessagingHosts\de.ai_shield.browser"

Get-ItemProperty `
  "HKLM:\SOFTWARE\Microsoft\Edge\NativeMessagingHosts\de.ai_shield.browser"
```

1. Oeffne in Chrome `chrome://policy` oder in Edge `edge://policy`.
2. Lade die Policies neu.
3. Pruefe, dass die Erweiterung mit genau der erwarteten ID installiert ist.
4. Oeffne eine Testseite und starte einen harmlosen Download.
5. Pruefe das Event Log:

```powershell
Get-WinEvent -FilterHashtable @{LogName="Application"; ProviderName="AIShieldBrowser"} `
  -MaxEvents 10 | Format-List TimeCreated,Id,Message
```

Die Ereignisse duerfen keine Cookies, Formulardaten, Querywerte oder Seiteninhalte enthalten.

### A.5 Browser-Rollback

Entferne zuerst die Extension-Force-Install-Policy ueber die zentrale Browserverwaltung. Entferne
danach die Native-Messaging-Registrierung und den Host nur in einer administrativen Wartung:

```powershell
Remove-Item "HKLM:\SOFTWARE\Google\Chrome\NativeMessagingHosts\de.ai_shield.browser" `
  -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item "HKLM:\SOFTWARE\Microsoft\Edge\NativeMessagingHosts\de.ai_shield.browser" `
  -Recurse -Force -ErrorAction SilentlyContinue
```

Loesche keine zentrale Browserpolicy, die nicht eindeutig AI Shield gehoert.

## Teil B: Windows Event Forwarding

### B.1 Collector vorbereiten

Dieser Schritt erfolgt auf einem Windows-Server, nicht auf dem geschuetzten Desktop.

1. Der Server benoetigt ein Zertifikat mit Server-Authentication-EKU.
2. DNS-Name und Zertifikatsname muessen zusammenpassen.
3. Die ausstellende CA muss vom Desktop vertraut werden.
4. Der HTTPS-WinRM-/WEC-Endpunkt muss erreichbar sein.
5. Der WEC-Administrator muss eine Source-Initiated-Subscription mit den gewuenschten Kanaelen und
   XPath-Filtern anlegen.

Auf dem Collector kann ein Administrator die WEC-Grundkonfiguration starten:

```powershell
wecutil.exe qc
```

Die AI-Shield-Source-Konfiguration ersetzt nicht die Subscription auf dem Collector.

### B.2 Zertifikatpin auf dem Collector auslesen

Der Administrator waehlt das Zertifikat anhand Subject und Ablaufdatum aus:

```powershell
Get-ChildItem Cert:\LocalMachine\My | `
  Select-Object Subject,NotAfter,Thumbprint,@{
    Name="SHA256";
    Expression={$_.GetCertHashString(
      [Security.Cryptography.HashAlgorithmName]::SHA256)}
  }
```

Verwende den 64-stelligen Wert aus `SHA256`, nicht den 40-stelligen SHA-1-Thumbprint.

### B.3 Erreichbarkeit vom Desktop pruefen

```powershell
Test-NetConnection wec.example.internal -Port 5986
```

Der DNS-Name muss derselbe sein, der anschliessend in der Collector-URI verwendet wird.

### B.4 WEF auf dem Desktop konfigurieren

```powershell
$collector = "https://wec.example.internal:5986/wsman/SubscriptionManager/WEC"
$pin = "<64_ZEICHEN_SHA256_DES_SERVERZERTIFIKATS>"

powershell -ExecutionPolicy Bypass `
  -File platform\windows\wef\configure_wef.ps1 `
  -Action apply `
  -CollectorUri $collector `
  -CertificateSha256 $pin `
  -ConfirmSystemChange
```

### B.5 Erfolg pruefen

```powershell
powershell -ExecutionPolicy Bypass `
  -File platform\windows\wef\configure_wef.ps1 -Action inspect

powershell -ExecutionPolicy Bypass `
  -File platform\windows\wef\configure_wef.ps1 -Action validate

Get-ScheduledTask -TaskName AIShieldWefPinValidation
```

`validate` muss Exitcode 0 liefern. Auf dem Collector muessen anschliessend neue Quellrechner und
Ereignisse in `ForwardedEvents` sichtbar werden. Bei einem Zertifikatswechsel muss zuerst der neue
Pin kontrolliert verteilt werden. Andernfalls deaktiviert der Waechter die Weiterleitung absichtlich.

### B.6 WEF-Rollback

```powershell
powershell -ExecutionPolicy Bypass `
  -File platform\windows\wef\configure_wef.ps1 `
  -Action rollback -ConfirmSystemChange
```

## Teil C: Datenschutzgerechte PowerShell-Weiterleitung

### C.1 Anforderungen an den SOC-Endpunkt

Das SOC-Team muss einen HTTPS-Endpunkt bereitstellen, der:

- `POST` mit `Content-Type: application/json` akzeptiert,
- bei Erfolg einen HTTP-Status von 200 bis 299 liefert,
- ein von Windows vertrautes Serverzertifikat verwendet,
- Arrays mit Event-Metadaten annimmt,
- keine Erwartung auf Klartext-Scriptinhalte besitzt.

Ein Datensatz enthaelt nur Record-ID, Event-ID, UTC-Zeit, Provider, Nachrichtenlaenge,
Computername und `message_hmac`.

### C.2 Zertifikatpin beschaffen

Der SOC-Administrator ermittelt den SHA-256-Pin wie in Abschnitt B.2. Bei Load Balancern muss jedes
moegliche Serverzertifikat geplant werden. Der aktuelle Forwarder akzeptiert genau einen Pin; daher
muss der Load Balancer ein konsistentes Zertifikat praesentieren.

### C.3 Konfigurieren

```powershell
$endpoint = "https://soc.example.internal/api/powershell-events"
$pin = "<64_ZEICHEN_SHA256_DES_SERVERZERTIFIKATS>"

powershell -ExecutionPolicy Bypass `
  -File platform\windows\powershell_logging\powershell_privacy_forwarder.ps1 `
  -Action configure `
  -Endpoint $endpoint `
  -CertificateSha256 $pin `
  -ConfirmSystemChange
```

Der DPAPI-geschuetzte HMAC-Schluessel und der Zustandszeiger liegen unter
`C:\ProgramData\AIShield\powershell-logging` und sind nur fuer LocalSystem und Administratoren
zugreifbar.

### C.4 Testereignis und manueller Versand

Erzeuge einen harmlosen PowerShell-Aufruf:

```powershell
powershell.exe -NoProfile -Command "Get-Date | Out-Null"
```

Starte danach einmal manuell den Forwarder als Administrator:

```powershell
powershell -ExecutionPolicy Bypass `
  -File platform\windows\powershell_logging\powershell_privacy_forwarder.ps1 `
  -Action run
```

Pruefe Aufgabe und Einstellungen:

```powershell
Get-ScheduledTask -TaskName AIShieldPowerShellPrivacyForwarder
powershell -ExecutionPolicy Bypass `
  -File platform\windows\powershell_logging\powershell_privacy_forwarder.ps1 `
  -Action inspect
```

Das SOC-Team muss bestaetigen, dass ein Datensatz angekommen ist und kein Scripttext enthalten ist.
Der Zustandszeiger wird nur nach erfolgreicher HTTP-Antwort fortgeschrieben.

### C.5 Rollback

```powershell
powershell -ExecutionPolicy Bypass `
  -File platform\windows\powershell_logging\powershell_privacy_forwarder.ps1 `
  -Action rollback -ConfirmSystemChange
```

## Gemeinsame Fehlersuche

| Fehler | Wahrscheinliche Ursache | Massnahme |
|---|---|---|
| Browser meldet „native host not found“ | Extension-ID stimmt nicht mit `allowed_origins` ueberein | ID aus Store und Hostmanifest vergleichen |
| Browser-Host-Signatur ungueltig | Falscher Publisher oder Binaerdatei veraendert | Neu bauen, signieren und Publisher-Pin pruefen |
| WEF-Pinpruefung scheitert | Falsches Zertifikat, DNS-Name oder abgelaufene Kette | Zertifikat auf Collector und Desktop-Vertrauen pruefen |
| WEF ist verbunden, aber ohne Ereignisse | Collector-Subscription oder XPath fehlt | Subscription auf dem WEC-Server pruefen |
| PowerShell-Forwarder liefert HTTP-Fehler | Endpoint, Authentisierung oder API-Vertrag falsch | SOC-Serverlogs und 2xx-Antwort pruefen |
| Keine PowerShell-Ereignisse | Loggingpolicy noch nicht geladen oder kein Event 4103/4104 | Richtlinie und Operational-Kanal pruefen |
| Pin aendert sich unerwartet | Zertifikat wurde rotiert oder TLS wird terminiert | Aenderung mit Infrastrukturteam verifizieren, niemals blind neuen Pin setzen |

## Abnahmecheckliste

- [ ] Alle zwölf CTest-Ziele bestehen.
- [ ] Browser-Host besitzt eine gueltige Signatur des erwarteten Publishers.
- [ ] Verwaltete Extension-ID entspricht exakt `allowed_origins`.
- [ ] Browser-Test erzeugt ein minimiertes `AIShieldBrowser`-Ereignis.
- [ ] Collector-DNS, Zertifikatsname, Kette und SHA-256-Pin stimmen ueberein.
- [ ] WEF-Pinwaechter laeuft als SYSTEM.
- [ ] Collector empfaengt die freigegebenen Ereigniskanaele.
- [ ] PowerShell-Endpunkt antwortet mit 2xx.
- [ ] Externer PowerShell-Datensatz enthaelt keinen Scripttext.
- [ ] Rollbackbefehle wurden in der Testumgebung ausgefuehrt und protokolliert.
