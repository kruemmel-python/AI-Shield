# AI Shield Enterprise Control-Plane-Vertrag

Stand: 27. Juli 2026

## Zweck

Der Enterprise-Vertrag erweitert den lokalen AI-Shield-Sicherheitskern um verwaltbare
Geräteidentitäten, hierarchische Richtlinien, begrenzte Reaktionsaufträge, Fleet-Telemetrie und
Rollen-Trennung. Er enthält absichtlich keine Remote-Shell und keinen frei formulierbaren
Codeausführungskanal.

Die Implementierung befindet sich in:

- `include/ai_shield/enterprise_trust.hpp` und `src/enterprise_trust.cpp`;
- `include/ai_shield/enterprise_policy.hpp` und `src/enterprise_policy.cpp`;
- `include/ai_shield/enterprise_command.hpp` und `src/enterprise_command.cpp`;
- `include/ai_shield/fleet_telemetry.hpp` und `src/fleet_telemetry.cpp`;
- `include/ai_shield/enterprise_rbac.hpp` und `src/enterprise_rbac.cpp`.

## Geräteidentität und Enrollment

Eine Geräteidentität bindet Organisation, Standort, Gerät, Zertifikatsseriennummer,
Gültigkeitszeitraum, Hardwarebindung, SPKI-Hash und Enrollment-Epoche. Der Agent akzeptiert eine
Identität nur, wenn die über Windows CNG geprüfte Attestation zur Identität passt. Im strengen
Profil müssen TPM-Schlüsselattestation, Secure Boot und Measured Boot bestätigt sein.

Das Registry-Modell erkennt:

- dieselbe Geräte-ID mit abweichender Hardwarebindung;
- wiederverwendete Zertifikatsseriennummern;
- wiederverwendete öffentliche Geräteschlüssel;
- abgelaufene, noch nicht gültige oder widerrufene Zertifikate;
- Zertifikatsrotation mit falscher erwarteter Seriennummer.

Die lokale Windows-Konfiguration erfolgt erhöht:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\platform\windows\enterprise\enterprise_enrollment.ps1 `
  -Action configure `
  -OrganizationId 1001 `
  -SiteId 2001 `
  -ControlPlaneUri https://soc.example.invalid/ai-shield/ `
  -PinnedSpkiSha256 <64-stelliger-SPKI-SHA256> `
  -CertificateThumbprint <40-stelliger-Clientzertifikat-Thumbprint>
```

Das Werkzeug akzeptiert ausschließlich HTTPS, verlangt ein gültiges Client-Auth-Zertifikat mit
privatem Schlüssel im Zertifikatspeicher `LocalMachine\My`, speichert keinen privaten Schlüssel und
schützt den Enrollment-Zustand mit DPAPI im Maschinenkontext. Das Verzeichnis ist auf `SYSTEM` und
lokale Administratoren beschränkt.

Status und Rückbau:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\platform\windows\enterprise\enterprise_enrollment.ps1 -Action status

powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\platform\windows\enterprise\enterprise_enrollment.ps1 -Action remove
```

`remove` löscht absichtlich nicht das Clientzertifikat. Widerruf und Zertifikatslöschung sind
getrennte PKI-Vorgänge und müssen im Unternehmensprozess protokolliert werden.

## Signierte Richtlinien

Der Policy-Vertrag enthält Organisation, Scope, Parent-Version, Policy- und Security-Version,
Mindest-Agentversion, Gültigkeitsfenster, Rollout-Ring, Rollout-Prozent, Regelhash, Parent-Hash und
Signierer-Fingerprint.

Die Aktivierung scheitert bei:

- ungültiger Zertifikatkettenprüfung oder falschem Signierer-Pin;
- verändertem Envelope-Hash;
- abgelaufener oder noch nicht gültiger Policy;
- zu alter Agentversion;
- nicht monotoner Policyversion oder herabgesetzter Security-Version;
- fehlender Parent-Version bei nicht globalen Scopes;
- ungültigem oder leerem Rollout.

Policy- und Response-Envelopes können als detached CMS signiert und vor der Übergabe an den Core
gegen einen SHA-256-Zertifikatpin sowie die vollständige Zertifikatkette mit Online-Widerrufsprüfung
validiert werden:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\platform\windows\enterprise\enterprise_envelope_signature.ps1 `
  -Action sign -PayloadPath .\policy.bin -SignaturePath .\policy.p7s `
  -SigningCertificateThumbprint <40-stelliger-Thumbprint>

powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\platform\windows\enterprise\enterprise_envelope_signature.ps1 `
  -Action verify -PayloadPath .\policy.bin -SignaturePath .\policy.p7s `
  -TrustedCertificateSha256 <64-stelliger-Zertifikat-SHA256>
```

Der Verifizierer verlangt exakt einen Signierer. Ein offline nicht prüfbarer Widerrufsstatus gilt
fail-closed als Fehler; ein Betreiber muss deshalb CRL/OCSP-Erreichbarkeit oder einen kontrollierten
internen Widerrufsdienst bereitstellen.

Die Geräteauswahl eines Rings ist deterministisch aus Geräte-ID, Policyversion und Regelhash. Ein
Break-Glass-Override ist höchstens eine Stunde gültig und benötigt zwei unterschiedliche,
berechtigte Policy-Freigaben.

## Remote Response ohne Remote-Shell

Der Agent akzeptiert nur die fest codierten Aktionen:

`ISOLATE_NETWORK`, `RELEASE_NETWORK_ISOLATION`, `QUARANTINE_FILE`, `BLOCK_FILE_HASH`,
`BLOCK_PUBLISHER`, `BLOCK_DESTINATION`, `SUSPEND_PROCESS`, `TERMINATE_PROCESS`,
`COLLECT_INCIDENT`, `CAPTURE_USER_DATA_SNAPSHOT`, `VERIFY_RECOVERY_VAULT`,
`START_APPROVED_RESTORE`, `ROTATE_DEVICE_CERTIFICATE` und `ENTER_SAFE_MODE`.

Jeder Auftrag besitzt Command-ID, Nonce, Organisation, Zielgerät, Akteur, typisiertes Ziel,
Ausstellungs- und Ablaufzeit, Inhalts-Hash und Signierer-Fingerprint. Die maximale Lease beträgt
15 Minuten. Command-ID und Nonce werden gegen Wiederholung geprüft. Hochwirksame Aktionen wie
Prozessbeendigung, Freigabe der Netzwerkisolation, Restore, Zertifikatsrotation und Safe Mode
benötigen Dual Control.

Freie Kommandozeilen, PowerShell-Fragmente, Skripte oder Binärdownloads gehören nicht zum Vertrag.

## Fleet-Telemetrie

Ein Fleet-Batch enthält Geräte-, Boot-, Batch- und Ereignissequenzen, Policy-, Modell- und
Agentversion, Erstellungszeit, Priorität, Vorgängerhash, Payloadhash und Gerätesignierer. Der
Empfänger erkennt Sequenzlücken, Boot-Verwechslungen, Hashkettenbrüche und Inhaltsmanipulation.

Der Store-and-Forward-Puffer priorisiert:

1. kritische Eindämmung;
2. Response-Ereignisse;
3. Security-Telemetrie;
4. Betriebsdaten;
5. Diagnosedaten.

Bei Druck werden zuerst niedrig priorisierte Batches verworfen. Sind nur kritische und
Response-Batches vorhanden, wird neuer Inhalt mit `out_of_budget` abgewiesen statt unbemerkt
Beweisdaten zu verlieren. Acknowledgements entfernen ausschließlich bestätigte Sequenzen.

## Rollen und Funktionstrennung

Der Kern unterscheidet Viewer, Analyst, Responder, Policy Author, Policy Approver,
Recovery Operator, Auditor und Platform Admin. Policy-Erstellung und Policy-Freigabe sind getrennt.
Restore-Start und Restore-Freigabe sind getrennt. Dual Control akzeptiert nie zweimal dieselbe
Akteur-ID.

## Automatisierte Nachweise

`ai_shield_enterprise_tests` prüft Enrollment, Clone Detection, Rotation, Widerruf,
Anti-Rollback, Break Glass, Dual Control, Command-Replay, Telemetrie-Manipulation,
Sequenzprüfung und Pufferprioritäten. `ai_shield_windows_enterprise_contract` prüft DPAPI,
Client-Auth, SPKI-Pinning, ACLs und das Verbot von Remote-Ausführungsprimitiven.

## Externe Voraussetzungen

Der Quellcode erzeugt keine Unternehmens-PKI, keinen hochverfügbaren Collector und kein SOC.
Produktiver Betrieb benötigt weiterhin mindestens:

- getrennte Offline- und Online-Signierschlüssel;
- mTLS-Reverse-Proxy oder Control Plane mit Zertifikatswiderruf und Rotation;
- HSM- oder TPM-gestützte Schlüsselverwaltung;
- hochverfügbaren, manipulationsfernen Telemetriespeicher;
- reale Rollenquelle und privilegiertes Access Management;
- Datenschutz-, Aufbewahrungs- und Löschkonzept;
- Last-, Ausfall-, Replay-, Failover- und Disaster-Recovery-Tests;
- Microsoft-signierte Treiber, HLK/WHCP und unabhängige Sicherheitsprüfung.

Diese Punkte sind keine durch lokale Beispielwerte ersetzbaren Codefunktionen.
