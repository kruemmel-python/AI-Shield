# Prüfauftrag für unabhängiges Security Review

Stand: 15. Juli 2026

## Prüfgegenstand

AI Shield Private Desktop `2.0.0-rc.13`, insbesondere:

- WFP-, Minifilter- und ProcessGuard-Kernelcode;
- IOCTL-Verträge, Puffer-, Größen-, Sequenz- und Zugriffsprüfung;
- Kernel-/Broker-Grenze und ABI-1.2-zu-ABI-2.0-Übersetzung;
- Policy-Signatur, monotone Versionierung und Recovery;
- DPAPI-/TPM-Schlüsselpfade und HMAC-Verifikation;
- Dateihandle-, Reparse-, Hardlink-, ADS- und Quarantänerennen;
- AppContainer-, Job-Object-, Named-Pipe- und Deadline-Grenzen;
- Dienst-DACLs, Installationspfade, Update, Rollback und Deinstallation;
- WFP-Umleitung, IPv6, Fragmentierung, ICMPv6 und QUIC-Metadaten;
- lokale Datenschutz- und Auditgrenzen.

## Erwartete Methoden

1. Manuelles Kernel- und User-Mode-Code-Review durch mindestens zwei Prüfer.
2. Bedrohungsmodell mit Angreifern als Standardnutzer, Administrator, kompromittierter Prozess und
   entfernte Netzwerkquelle.
3. IOCTL-, Parser-, Policy-, Dateisystem- und Netzwerkfuzzing mit reproduzierbaren Seeds.
4. Driver Verifier, HVCI, Special Pool, Pool Tracking, I/O Verification und Deadlock Detection.
5. Versuche gegen TOCTOU, Reparse Points, Hardlinks, ADS, Volumegrenzen und Quarantänerestore.
6. Rechteausweitung, Dienstmanipulation, Update-Downgrade und Auditlöschung.
7. Fehlalarm- und Umgehungstests mit verbreiteter Privatsoftware und realistischen Angriffsketten.
8. Bericht mit Schweregrad, Reproduktionsschritten, betroffenen Versionen und Regressionstest.

## Übergabeartefakte

- `editions/private_desktop/RELEASE_CONTRACT.json`
- `runtime/private-release/RC_REPORT.json`
- `runtime/private-release/microsoft-submission/`
- `platform/windows/*/driver/`
- `platform/windows/common/`
- `tools/ai_shield_broker/`
- `platform/windows/policy/`, `security/`, `sandbox/` und `installer/`
- `tests/` sowie vorhandene Qualifikationsberichte

Der Auftrag gilt erst als unabhängig, wenn Auftragnehmer und Prüfer nicht an der Implementierung
der geprüften Komponenten beteiligt waren. AI Shield selbst kann diesen Nachweis nicht erzeugen.
