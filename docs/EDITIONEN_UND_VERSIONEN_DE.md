# AI Shield Editionen und Versionen

Stand: 14. Juli 2026

## Gemeinsame technische Basis

Alle Ausprägungen verwenden denselben C++23 Shared Core, dieselbe interne ABI 2.0, dieselbe
signierte Policylogik, dasselbe AISHAD02-Auditformat und dieselben drei Windows-Treiber:

- `AIShieldWfp.sys` für IPv4-/IPv6-Netzwerkmetadaten und WFP-Enforcement;
- `AIShieldMiniFilter.sys` für Dateiprovenance, Dateiidentität und Quarantänepfade;
- `AIShieldProcessGuard.sys` für Prozess-, Parent-, Image- und Handle-Regeln.

Der Kerneltransport ist als ABI `1.2`, Freeze-Revision `2`, eingefroren. Windows-Adapter validieren
die Kernelstrukturen und übersetzen sie an der Vertrauensgrenze in das interne ABI 2.0.

## Private Desktop

`editions/private_desktop` ist die Einzelplatzedition. Sie enthält eine lokale WPF-Oberfläche,
MSI-Installation und vollständige Deinstallation, Schutzschalter, Neustartfortsetzung, Browsersensor,
Dateityp-Schutz, Audit Viewer, Quarantänefreigabe sowie Recovery-Vault, Ransomware-Erkennung und
bestätigte Wiederherstellung. Zentrale Collector-, Flotten- und SOC-Dienste
sind nicht Voraussetzung für den normalen lokalen Betrieb.

## Enterprise-Betriebsprofil

Die Unternehmensausprägung ist derzeit kein zweiter abweichender Sicherheitskern. Sie kombiniert
die gemeinsame Plattform mit verwalteten Integrationen für Browser-Policies, WEF, SIEM, WDAC,
PowerShell-Metadatenweiterleitung, Firewall- und ASR-Rollout. Reale Endpunkte, Zertifikatpins,
Publisheridentitäten, Rollen und Aufbewahrungsregeln müssen durch das betreibende Unternehmen
bereitgestellt und qualifiziert werden.

## Developer Full

`AI_Shield_Developer_Full.zip` richtet sich an Entwicklerteams. Es enthält Quellcode, CMake-/WDK-
Buildpfade, Tests, Dokumentation und eine vorkompilierte Private-Desktop-Referenz. Buildartefakte und
lokale Testsignaturen werden bewusst von privaten Signierschlüsseln getrennt.

## HTTP-Gateway-Prototyp

`ai_shield_prototype.exe` ist der Labor- und Backend-Gatewaypfad. Er analysiert explizit darüber
geführten HTTP-Verkehr und ist nicht der Standardstart der Private-Desktop-Edition. Der systemweite
Schutz entsteht durch Treiber, Broker, Core und lokale Policy; ein freier Gatewayport ist dafür
nicht erforderlich.

## Versionsstatus

| Vertrag | Aktueller Stand |
|---|---|
| Release Candidate | `2.0.0-rc.9` |
| Kernel-Transport | `1.2` |
| ABI-Freeze | Revision `2` |
| Interne Ereignis-ABI | `2.0` |
| Policy-Schema | `1` |
| Auditformat | ausschließlich `AISHAD02` |

Eine Änderung an ABI, Policyformat oder eingefrorenem Consumer-Funktionsumfang benötigt einen
bewusst aktualisierten Releasevertrag und erneute Qualifikation der betroffenen Komponenten.
