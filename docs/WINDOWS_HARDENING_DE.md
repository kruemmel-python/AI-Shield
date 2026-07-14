# AI Shield: Sicheres Windows-Hardening

Stand: 14. Juli 2026

## Automatische Pruefung

`AI_Shield_Start.cmd` fuehrt vor der AI-Shield-Policyaktivierung eine rein lesende
Plattformpruefung aus. Der Bericht liegt in `runtime/security-posture.json`; die danebenliegende
SHA-256-Datei erlaubt die Erkennung nachtraeglicher Aenderungen. Geprueft werden:

- Secure Boot und TESTSIGNING,
- TPM 2.0 und der optionale AI-Shield-TPM-Anker,
- VBS/HVCI Memory Integrity und Credential Guard,
- Defender-Echtzeitschutz und Windows-Firewallprofile,
- Defender-Tamper-, Cloud-, Netzwerk-, PUA- und Controlled-Folder-Schutz,
- Microsofts Blockliste verwundbarer Treiber,
- erzwungene ASR-Regeln,
- Betriebssystem-Volumeverschluesselung,
- LSA-PPL, UAC, SMB1 und RDP Network Level Authentication,
- PowerShell Script-Block- und Module-Logging,
- ACL-geschuetzte Installationspfade der AI-Shield-Dienste.

Die Pruefung kann separat gestartet werden:

```powershell
.\AI_Shield_Sicherheitsstatus.cmd
```

Automatisierungs- und Laborumgebungen koennen mit `-FailOnCritical` einen Exitcode ungleich null bei
kritischen Befunden verlangen:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File platform\windows\security\system_security_posture.ps1 -FailOnCritical
```

## Warum AI Shield die Windows-Einstellungen nicht ungefragt aendert

HVCI kann inkompatible Treiber am Start hindern. ASR und WDAC koennen Fachanwendungen blockieren.
Firewallregeln koennen Server-, VPN- und Entwicklungsworkflows unterbrechen. BitLocker ohne sicher
verwahrten Recovery-Key kann Daten unzugreifbar machen. Secure Boot kann die lokal testsignierten
Prototyptreiber nicht laden. Deshalb bleibt die Erkennung automatisch, die Betriebssystemaenderung
aber ein dokumentierter, getesteter Administratorvorgang.

## Reversible Defender-Auditbaseline

Die Auditbaseline fuegt fehlende empfohlene ASR-Regeln im Auditmodus hinzu und versetzt Defender
Network Protection sowie Controlled Folder Access in den Auditmodus. PUA-Schutz wird ebenfalls
mindestens auditierend aktiviert. Vorher wird der exakte Zustand unter
`C:\ProgramData\AIShield\hardening` gesichert. Bereits erzwungene Regeln werden nicht abgeschwaecht.

```powershell
.\AI_Shield_Defender_Auditmodus.cmd
```

Rollback auf den vorherigen Zustand:

```powershell
.\AI_Shield_Defender_Rollback.cmd
```

Der Auditmodus blockiert nicht, erzeugt aber Messdaten fuer eine spaetere, gezielte Freigabe
einzelner Regeln. Die Skripte verlangen UAC und eine explizite Systemaenderungsbestaetigung.

## Dienst- und Binaerschutz

Broker und Core werden nicht mehr aus dem Entwicklerverzeichnis ausgefuehrt. Der Installer kopiert
sie nach `C:\Program Files\AIShield\bin`, vergleicht den SHA-256-Wert nach dem Kopieren, entfernt
vererbte Schreibrechte und beschraenkt Dienststeuerung und Konfigurationsaenderung auf LocalSystem
und Administratoren. Authentifizierte Benutzer erhalten nur Leserechte auf den Dienststatus.

## Schutzstufen

`AI_Shield_Start.cmd` aktiviert die kompatibilitaetsorientierte systemweite Policy. Sie blockiert
Quarantaene- und User-Temp-Ausfuehrung, riskante Script-/LOLBin-Kombinationen, Office-Kindprozesse
und typische Wurm-Egress-Ports.

`AI_Shield_Protect_System_Strict.cmd` aktiviert zusaetzlich Browser-Portbegrenzung,
unaufgeforderte-Inbound-Sperre und direkte Ausfuehrung aus Downloads. Dieser Modus ist fuer einen
kontrollierten Pilotbetrieb gedacht und kann legitime Anwendungen blockieren.

## Nicht lokal loesbare Grenzen

Firmwarekompromittierung kann durch Measured Boot und externe Attestierung erkannt, aber nicht
zuverlaessig aus demselben kompromittierten Rechner repariert werden. Ein uneingeschraenkter lokaler
Administrator kann lokale Schutzkomponenten letztlich manipulieren; externe SIEM-Weiterleitung und
getrennte Administratoridentitaeten begrenzen dieses Risiko. Verschluesselte TLS-/QUIC-Inhalte
bleiben ohne verwaltete Browserintegration oder expliziten TLS-Proxy unsichtbar.
