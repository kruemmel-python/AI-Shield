# AI Shield: Enterprise-Sicherheitsintegrationen

Stand: 13. Juli 2026. Diese Integrationen bilden das verwaltete Enterprise-Betriebsprofil; die
Einzelplatzedition und ihre lokale Browserinstallation sind in
[`PRIVATE_DESKTOP_HANDBUCH_DE.md`](PRIVATE_DESKTOP_HANDBUCH_DE.md) getrennt dokumentiert.

Eine ausfuehrliche Schritt-fuer-Schritt-Anleitung mit Abnahme und Fehlersuche steht in
`JUNIOR_ENTERPRISE_INTEGRATION_SCHNELLSTART_DE.md`.

## Browser-Sensor

Die Manifest-V3-Erweiterung erfasst Hauptnavigationen sowie Start und Abschluss von Downloads. Sie
uebermittelt Schema, Ereignis-ID, Zeit, Tab/Frame, Transition sowie URL-Schema, Host, Port,
Pfadlaenge und das Vorhandensein einer Query. Seiteninhalt, kompletter Pfad, Querywerte, Cookies,
Formulardaten und HTTP-Header werden nicht erfasst.

Der Native-Messaging-Host akzeptiert maximal 64 KiB grosse, einzeilige UTF-8-JSON-Objekte und
schreibt sie in die Windows-Event-Log-Quelle `AIShieldBrowser`. Der Installer verlangt eine gueltige
Authenticode-Signatur mit explizitem Publisher-Pin. Fuer einen verwalteten Rollout werden die
Extension-ID und eine HTTPS-Update-URL aus dem Unternehmens-Extension-Store benoetigt:

```powershell
powershell -ExecutionPolicy Bypass `
  -File platform\windows\browser_extension\install_browser_sensor.ps1 `
  -ExtensionId <32-Zeichen-ID> `
  -PublisherThumbprint 125D756E7666534CDF4558A2B9E96E96907B3FFC `
  -UpdateUrl https://management.example/extensions/update.xml `
  -ConfirmSystemChange
```

Der gezeigte Thumbprint ist nur der lokale Prototyp-Publisher. Produktion benoetigt das reale
Code-Signing-Zertifikat und einen entsprechend geaenderten Pin.

## Windows Event Forwarding mit Zielpin

Die Source-Manager-Policy akzeptiert nur HTTPS. Vor Aktivierung werden Windows-Zertifikatskette und
SHA-256-Zertifikatpin geprueft. Ein SYSTEM-Task validiert alle fuenf Minuten erneut. Bei Abweichung
wird die Forwarding-Policy entfernt und ein lokaler Fehler protokolliert.

```powershell
powershell -ExecutionPolicy Bypass -File platform\windows\wef\configure_wef.ps1 `
  -Action apply -CollectorUri https://wec.example:5986/wsman/SubscriptionManager/WEC `
  -CertificateSha256 <64-HEX> -ConfirmSystemChange

powershell -ExecutionPolicy Bypass -File platform\windows\wef\configure_wef.ps1 `
  -Action rollback -ConfirmSystemChange
```

Der Collector muss die Source-Initiated-Subscription und deren Kanal/XPath-Auswahl separat besitzen.

## WDAC-Auditbaseline

Die Policy gilt fuer den geschuetzten AI-Shield-Installationsbaum und enthaelt explizit `Audit Mode`.
`CiTool`-Operationen haben ein Zeitlimit; Erfolg und Rollback werden anhand der privilegierten
Policy-Inventur bestaetigt. Event 3076 wird gruppiert ausgewertet. Null Ereignisse allein reichen
nicht fuer Enforcement, solange kein repraesentativer Soak-Zeitraum nachgewiesen ist.

```powershell
powershell -ExecutionPolicy Bypass -File platform\windows\wdac\wdac_audit_baseline.ps1 `
  -Action evaluate -LookbackDays 14
powershell -ExecutionPolicy Bypass -File platform\windows\wdac\wdac_audit_baseline.ps1 `
  -Action rollback -ConfirmSystemChange
```

## Datenschutzgerechtes PowerShell-Logging

Die Konfiguration aktiviert Script-Block-Logging ohne Invocation-Logging und begrenztes
Microsoft-PowerShell-Modul-Logging. Der externe HTTPS-Payload enthaelt keinen Scripttext, sondern nur
Record-ID, Event-ID, UTC-Zeit, Provider, Nachrichtenlaenge, Computername und einen HMAC-SHA-256. Der
HMAC-Schluessel liegt DPAPI-Machine-geschuetzt. TLS-Kette und Serverzertifikatpin muessen passen.

```powershell
powershell -ExecutionPolicy Bypass `
  -File platform\windows\powershell_logging\powershell_privacy_forwarder.ps1 `
  -Action configure -Endpoint https://soc.example/api/powershell-events `
  -CertificateSha256 <64-HEX> -ConfirmSystemChange
powershell -ExecutionPolicy Bypass `
  -File platform\windows\powershell_logging\powershell_privacy_forwarder.ps1 `
  -Action rollback -ConfirmSystemChange
```

## Firewall-Baseline

Vor jeder Aenderung wird die vollstaendige Firewallkonfiguration als `.wfw` exportiert. Die Baseline
aktiviert alle Profile mit Inbound-Block und Outbound-Allow. Bestehende Regeln bleiben erhalten.
VPN-Programme koennen als EXE-Pfade, Entwicklungsports nur fuer Private Profile und `LocalSubnet`
freigegeben werden.

```powershell
powershell -ExecutionPolicy Bypass -File platform\windows\firewall\firewall_baseline.ps1 `
  -Action apply -VpnProgram C:\Program Files\Vendor\vpn.exe `
  -DevelopmentPort 18080,18081 -ConfirmSystemChange
powershell -ExecutionPolicy Bypass -File platform\windows\firewall\firewall_baseline.ps1 `
  -Action rollback -ConfirmSystemChange
```

## UAC-Assistent

Der Assistent aendert UAC nie selbst. Er prueft EnableLUA, Admin-Consent, Secure Desktop und den
eingebauten Administrator. Optional erzeugt er eine sichtbare `.reg`-Empfehlung zur manuellen
Pruefung; `applied` bleibt immer `false`.

```powershell
powershell -ExecutionPolicy Bypass -File platform\windows\uac\uac_hardening_assistant.ps1
powershell -ExecutionPolicy Bypass -File platform\windows\uac\uac_hardening_assistant.ps1 `
  -Action generate-reg -OutputPath runtime\AIShield-UAC-Recommendation.reg
```

## ASR-Evidenzauswertung

Die Auswertung liest Defender-Auditereignis 1122, gruppiert nach Regel und Anwendung und markiert
Regeln nur nach Mindestmenge und begrenzter Anwendungsstreuung als Kandidaten fuer manuelle
Pruefung. Sie veraendert keine Defender-Policy und setzt `auto_enforced` immer auf `false`.

```powershell
powershell -ExecutionPolicy Bypass -File platform\windows\asr\evaluate_asr_audit.ps1 `
  -LookbackDays 14 -MinimumEvents 20 -MaximumDistinctApplications 5 `
  -OutputPath runtime\asr-evidence.json
```
