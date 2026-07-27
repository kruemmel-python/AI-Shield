# RC15 Enterprise-, Paket- und Installationsnachweis

Stand: 27. Juli 2026, Release Candidate `2.0.0-rc.15`

## Änderungen gegenüber RC14

RC15 ergänzt den lokalen Sicherheitskern um getestete Enterprise-Agent-Verträge:

- Geräte-Enrollment mit Organisations-, Standort- und Geräteidentität;
- TPM-bindbare Attestation, Clone Detection, Zertifikatsrotation und Widerruf;
- signierte Policyhierarchie mit Anti-Rollback, Ablaufzeiten und Rollout-Ringen;
- Dual-Control-Break-Glass mit begrenzter Gültigkeit;
- feste Remote-Response-Aktionen ohne Remote-Shell, mit Lease, Nonce und Anti-Replay;
- RBAC und Funktionstrennung;
- signierte, hashverkettete Fleet-Batches mit Sequenzprüfung und priorisiertem Offlinepuffer;
- DPAPI-geschütztes Windows-Enrollment sowie detached CMS mit Zertifikatpin und
  Online-Widerrufsprüfung;
- Control Flow Guard, CET, ASLR und DEP/NX für User-Mode-Binärdateien.

Bewusst nicht übernommen wurden GPU-Enforcement im WFP-Pfad, DMA-RAM-Scanning, eine neue
Kernel-Bytecode-VM und selbst entwickelte CFI/PAC-Verfahren. Diese Ansätze würden die
Kernelangriffsfläche und Zertifizierungsrisiken erhöhen.

## Automatisierte Verifikation

Der Release- und Debug-Build bestanden jeweils alle 18 CTest-Ziele. Die zusätzlichen Tests prüfen
Enrollment, Clone Detection, Rotation, Widerruf, Anti-Rollback, Break Glass, Dual Control,
Command-Replay, Telemetriemanipulation, Sequenzlücken, Pufferprioritäten, DPAPI-, Zertifikat-,
SPKI- und CMS-Verträge.

## Pakete

Die aus diesem Stand erzeugten Artefakte sind:

- `AI_Shield_Private_Desktop.zip`;
- `AI_Shield_Private_Desktop_2.0.0-rc.15.zip`;
- `AI_Shield_Private_Desktop_2.0.0-rc.15_x64.msi`;
- `AI_Shield_Developer_Full.zip`;
- `SHA256SUMS-2.0.0-rc.15.txt`.

Die endgültigen Hashes werden aus den fertigen Artefakten erzeugt und als separates
`SHA256SUMS-2.0.0-rc.15.txt` veröffentlicht. Interne Paketmanifeste prüfen jede enthaltene Datei.

## Installationsnachweis

Die Installation verwendet ausschließlich das fertig gebaute und lokal Authenticode-signierte
RC15-MSI. Vorhandene ältere MSI-Versionen werden über den stabilen UpgradeCode entfernt.
Anschließend werden WFP-, Minifilter- und ProcessGuard-Treiber, Broker, Core, Desktop-UI und
Tray-Agent installiert und ihr Laufzeitzustand geprüft.

## Grenzen

Lokale Testsignaturen sind keine Microsoft-Produktionstreibersignaturen. Öffentliche Auslieferung
unter aktivem Secure Boot benötigt weiterhin Partner Center, HLK/WHCP, Microsoft-Signierung,
Hardware- und Kompatibilitätsmatrix sowie unabhängige Sicherheitsprüfung. Eine reale Enterprise-
Control-Plane, PKI/HSM, Identitätsquelle und manipulationsferne Collector-Infrastruktur sind
deployment-spezifische Voraussetzungen.
