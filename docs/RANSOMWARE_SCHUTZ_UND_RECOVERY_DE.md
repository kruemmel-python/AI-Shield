# Ransomware-Schutz und Wiederherstellung

Stand: 14. Juli 2026, Release Candidate `2.0.0-rc.12`

## Ziel und Sicherheitsmodell

AI Shield kombiniert für private Windows-Rechner vier getrennte Kontrollen:

1. Der Minifilter erfasst Schreib- und Umbenennungsereignisse in Downloads, Desktop, Dokumenten,
   Bildern, Musik, Videos und Benutzer-Temp.
2. Der Broker korreliert Ereignisse pro Prozess. Schreibserien, destruktive Operationen und viele
   unterschiedliche Dateiobjekte erzeugen ein dauerhaftes Kernel-Signal.
3. Der Recovery-Vault hält bekannte Dateistände in einem inhaltsadressierten SHA-256-Objektspeicher.
4. Die Desktop-UI erkennt Veränderungen, zeigt Vorfälle und führt nur bestätigte, hashverifizierte
   Wiederherstellungen aus.

Das ist zusätzlicher Schutz gegen typische Verschlüsselungs- und Löschserien. Es ersetzt nicht
Defender, Controlled Folder Access, BitLocker, Secure Boot, Updates oder ein getrenntes Backup.

## Versionsspeicher

Der Standardpfad ist `C:\ProgramData\AIShield\recovery-vault`. Bei erhöhtem Start wird die
Vererbung entfernt; nur `SYSTEM` und lokale Administratoren erhalten Vollzugriff. Binärinhalte
werden einmal unter ihrem SHA-256-Hash gespeichert. Snapshots referenzieren Pfad, Hash, Größe,
Zeitpunkt, Entropie und Canary-Status. Standardgrenzen sind 10 GiB pro Vault und 512 MiB pro Datei.
Übersprungene Dateien und Ursachen stehen im Snapshot-Manifest.

Die Auflistung folgt keinen Reparse Points. Junctions, symbolische Links und nicht auflösbare
Kompatibilitätsverweise werden übersprungen, bevor ein Zielpfad betreten wird. Unzugängliche oder
während des Snapshots entfernte Einträge werden pro Datei beziehungsweise Verzeichnis abgefangen,
ohne einen erfolgreichen Snapshotabschluss vorzutäuschen. Dadurch entstehen weder Junction-
Schleifen noch unbeabsichtigte Sicherungen außerhalb der festgelegten Schutzwurzeln.

Die belegte Vault-Größe wird zu Beginn eines Snapshots einmal bestimmt und danach mit einem
laufenden Zähler fortgeschrieben. Snapshotdatensätze und Fehlerlisten wachsen linear. Die
Integritätsprüfungen werden nicht reduziert: Quelle, temporäres Objekt und Inhaltsadresse bleiben
SHA-256-gebunden.

Die Installation erzeugt nur dann eine Baseline, wenn noch kein Snapshot vorhanden ist. Neustart,
UI-Refresh oder erneuter Schutzstart ersetzen sie nicht. Weitere Stände werden in der UI bewusst mit
**Jetzt sichern** angelegt.

Auf dem Referenzrechner wurde die erste reale Baseline am 13. Juli 2026 erfolgreich erstellt:
`13.353` erfasste Dateien, `0` übersprungene Dateien, Snapshot-ID
`20260713T1707257435075Z`. Die Erstbaseline dauerte aufgrund des tatsächlichen Hashens,
Entropiemessens und Kopierens mehrere Minuten; spätere Statusabfragen verwenden das vorhandene
Manifest und lösen nicht automatisch einen neuen Snapshot aus.

## Erkennung und Containment

Canary-Löschung oder -Änderung führt zu einem bestätigten Vorfall. Daneben bewertet der Scanner
Änderungs- und Löschserien sowie starke Entropiezunahme. Der portable C++-Detektor bewertet pro
Prozess Write-, Rename-, Remove-, Truncate-, Canary- und Recovery-Tamper-Ereignisse.

Der Broker schreibt Echtzeitsignale nach
`C:\ProgramData\AIShield\recovery-vault\kernel-signals.jsonl`. Automatisches Prozess-Suspendieren ist
nicht Standard, da ein Fehlalarm Windows oder legitime Anwendungen stilllegen könnte. Die
administrative API kann einen konkret identifizierten Nicht-Systemprozess nach Bestätigung
suspendieren und seine ausgehenden Verbindungen blockieren. Windows-, System- und
AI-Shield-Prozesse werden abgelehnt.

## Wiederherstellung

**Wiederherstellungsplan** ist eine reine Vorschau. **Ausgewählten Stand wiederherstellen** verlangt
eine Bestätigung. Vor dem Ersetzen wird eine vorhandene Zieldatei in den Konfliktspeicher verschoben.
Objekt und temporäre Zieldatei werden erneut per SHA-256 geprüft. Ziele außerhalb der konfigurierten
Benutzerordner werden abgelehnt. AI Shield schreibt im laufenden Windows keine Systemdateien zurück.

## Externe Sicherung

**Extern sichern** kopiert Vault, Snapshots und Vorfälle in einen datierten Ordner und erzeugt
`backup-manifest.json` mit Größe und SHA-256 jeder Datei. Ein Ziel innerhalb des lokalen Vaults oder
eines geschützten Benutzerordners wird abgelehnt. Gegen Administrator-Ransomware,
Datenträgerausfall und Geräteverlust muss das Ziel anschließend getrennt oder serverseitig
unveränderlich sein.

## Administrative Referenz

```powershell
$admin = '.\platform\windows\admin\ai_shield_admin.ps1'
powershell -ExecutionPolicy Bypass -File $admin -Action ransomware-status
powershell -ExecutionPolicy Bypass -File $admin -Action ransomware-snapshot
powershell -ExecutionPolicy Bypass -File $admin -Action ransomware-detect
powershell -ExecutionPolicy Bypass -File $admin -Action ransomware-incidents
powershell -ExecutionPolicy Bypass -File $admin -Action ransomware-restore-plan -IncidentId <ID>
powershell -ExecutionPolicy Bypass -File $admin -Action ransomware-restore -IncidentId <ID> -ConfirmRestore
```

Direkte externe Sicherung und Prüfung:

```powershell
$recovery = '.\platform\windows\ransomware\ransomware_recovery.ps1'
powershell -ExecutionPolicy Bypass -File $recovery -Action backup -BackupRoot E:\AIShieldBackup
powershell -ExecutionPolicy Bypass -File $recovery -Action verify-backup -BackupRoot E:\AIShieldBackup\AIShield-Recovery-<Zeit>
```

## Nachweise und Grenzen

Der automatisierte Test erzeugt einen bekannten Stand, verändert eine Datei, löscht den Canary,
erwartet einen bestätigten Vorfall, prüft den Plan, stellt den Inhalt wieder her und verifiziert eine
externe Sicherung. Das beweist den kontrollierten Funktionspfad, nicht die Wirksamkeit gegen jede
Ransomware. Der Test enthält zusätzlich eine defekte Windows-Junction und verlangt, dass sie ohne
Abbruch und ohne Verfolgung des Zielpfads übersprungen wird. Ausstehend bleiben Stromausfall-,
Vollplatten-, 24-Stunden-/30-Tage-, Driver-Verifier-,
HVCI-, HLK-, Fehlalarm- und unabhängige Penetrationstests. Offline-Systemwiederherstellung und ein
unveränderlicher externer Speicher benötigen weiterhin ein reales, qualifiziertes Zielmedium und
Recovery-Labor.
