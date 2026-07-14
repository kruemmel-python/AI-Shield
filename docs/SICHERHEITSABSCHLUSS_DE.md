# AI Shield: Abschluss der offenen Windows-Sicherheitsfunktionen

Stand: 14. Juli 2026

## Bereits lokal aktiviert

- Credential Guard ohne UEFI-Lock ist mit `LsaCfgFlags=2` vorbereitet. Die Aktivierung wird erst
  nach einem kontrollierten Windows-Neustart messbar.
- Defender Cloud Protection verwendet Advanced MAPS, Safe Samples und Block-at-First-Seen.
- PowerShell Script-Block- und Microsoft-Modul-Logging sind lokal aktiv. Invocation-Logging bleibt
  aus Datenschutzgruenden deaktiviert.
- Alle Aenderungen besitzen ACL-geschuetzte Backups und Rollbackpfade.

Lokalen Zustand und Rollback pruefen:

```powershell
powershell -ExecutionPolicy Bypass `
  -File platform\windows\security\complete_local_security.ps1 -Action inspect

powershell -ExecutionPolicy Bypass `
  -File platform\windows\security\complete_local_security.ps1 `
  -Action rollback -ConfirmSystemChange
```

## BitLocker

AI Shield startet keine Verschluesselung, bevor ein externes Recovery-Verzeichnis angegeben wurde.
Das Ziel darf nicht auf dem zu verschluesselnden Betriebssystemvolume liegen. Zulaessig sind etwa
ein administrativ geschuetzter UNC-Pfad oder ein kontrollierter Wechseldatentraeger.

```powershell
powershell -ExecutionPolicy Bypass -File platform\windows\security\prepare_bitlocker.ps1 `
  -Action enable -RecoveryDirectory \\recovery-server\bitlocker$\CLIENT-01 `
  -ConfirmEncryption
```

Das Skript erzeugt zuerst einen Recovery-Password-Protector, schreibt und verifiziert das
Recovery-Dokument am externen Ziel und fordert erst danach XTS-AES-256 mit TPM-Protector an.
Hardwaretest und Neustart bleiben ein kontrollierter Betriebsschritt.

## Nicht lokal erzwingbare Tamper Protection

Tamper Protection wird ueber Windows Security, Microsoft Intune oder Configuration Manager
verwaltet. Direkte Aenderungen des Registry-Anzeigewerts sind weder wirksam noch unterstuetzt. Fuer
einen verwalteten Abschluss werden Defender-for-Endpoint-Onboarding und eine zugewiesene Intune-
Antiviruspolicy benoetigt. Auf einem Einzelplatzsystem muss der Administrator die Funktion in
Windows Security unter Viren- und Bedrohungsschutz aktivieren und danach den Posture-Bericht erneut
ausfuehren.

## Noch benoetigte externe Parameter

| Funktion | Benoetigte Werte |
|---|---|
| Verwalteter Browser-Rollout | Enterprise-Extension-ID, HTTPS-Update-URL, Publisher-Thumbprint; die lokale Private-Desktop-Erweiterung kann manuell geladen werden |
| WEF | Collector-URI, SHA-256-Pin des Collector-Zertifikats |
| PowerShell-Forwarding | SOC-HTTPS-Endpunkt, SHA-256-Pin des Serverzertifikats |
| BitLocker | Externes, geschuetztes Recovery-Verzeichnis |

Die exakten Installationsbefehle stehen in `JUNIOR_ENTERPRISE_INTEGRATION_SCHNELLSTART_DE.md`.

## ASR-Enforcement

Die zwoelf Regeln laufen im Auditmodus. Der vorhandene Korpus enthaelt erst zwei Auditereignisse
einer Regel und erfuellt den konfigurierten Mindestwert von zwanzig Ereignissen nicht. Automatisches
Enforcement wuerde die zuvor festgelegte Fehlalarm- und Allowlist-Grenze umgehen und bleibt deshalb
gesperrt. Die erneute Auswertung erfolgt mit:

```powershell
powershell -ExecutionPolicy Bypass -File platform\windows\asr\evaluate_asr_audit.ps1 `
  -LookbackDays 14 -MinimumEvents 20 -MaximumDistinctApplications 5 `
  -OutputPath runtime\asr-evidence.json
```

Nur Regeln mit ausreichender Evidenz, geklaerten Anwendungen und dokumentierter Rollbackfreigabe
duerfen anschliessend einzeln von Audit auf Block umgestellt werden.
