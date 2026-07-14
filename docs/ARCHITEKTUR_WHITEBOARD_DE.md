# AI Shield Architektur-Whiteboard

Stand: 13. Juli 2026

```mermaid
flowchart LR
    Client["Client IPv4 / IPv6"] --> WFP["AIShieldWfp.sys"]
    WFP --> Gateway["HTTP Gateway"]
    Gateway --> Core["Shared Core\nParser, Evidenz, Policy"]
    Core --> Backend["Geschütztes Backend"]
    Core --> Decision["Block / Allow / Redirect"]

    Mini["AIShieldMiniFilter.sys\nFile + Volume ID"] --> Broker["AIShieldBroker"]
    Guard["AIShieldProcessGuard.sys\nProcess + Parent ID"] --> Broker
    ETW["ETW Sensor"] --> ABI2
    AMSI["AMSI Sensor"] --> ABI2
    WFP --> Broker
    Broker --> ABI2["ABI 2.0 + HMAC"]
    ABI2 --> Audit["AISHAD02 Audit"]
    Audit --> Viewer["Private Desktop Audit Viewer"]
    ABI2 --> Graph["Kausalgraph / Incident / Replay"]

    Browser["Edge / Chrome Sensor"] --> Broker
    Download["MOTW Download"] --> Scanner["Isolierter AMSI / PDF / ZIP Scanner"]
    Scanner --> Mini

    Runtime["DPAPI Runtime-State\nKey + Policy + Model"] --> Broker
    Policy["Signierte monotone Policy"] --> Runtime
    Policy --> WFP
    Policy --> Mini
    Policy --> Guard

    Watchdog["AIShieldCore\nBackoff + Safe Mode"] --> WFP
    Watchdog --> Mini
    Watchdog --> Guard
    Watchdog --> Broker
    Watchdog --> Health["health.json + Event Log"]

    Admin["Erhöhte Admin-/SOC-API"] --> Watchdog
    Admin --> Broker
    Admin --> Audit
    SIEM["CEF / LEEF / JSON\nSyslog IPv4 / IPv6"] <-- ABI2
    SOC["Lokale SOC-Konsole"] --> Admin
    Update["CMS/Authenticode A/B Update"] --> Watchdog
```

## Aktiver Maschinenzustand

```text
Treiber:      WFP, MiniFilter, ProcessGuard = RUNNING
Dienste:      AIShieldBroker, AIShieldCore = RUNNING / AUTO
Runtime:      DPAPI-geschützt; Generation und Policy sind monoton und laufzeitabhängig
TPM:          Platform Provider hardware-backed, Anchor vorhanden
Health:       safe_mode=false, unhealthy_components=0, audit_writable=true
Gateway:      optional; für den systemweiten Private-Desktop-Schutz nicht erforderlich
Auditformat:  ausschließlich AISHAD02
```

## Vertrauensgrenzen

1. Kernelereignisse sind nicht vertrauenswürdig und werden vor Core-Nutzung validiert.
2. ABI 1.2 endet am Windows-Adapter; intern gilt ausschließlich ABI 2.0.
3. Audit akzeptiert ausschließlich `AISHAD02`.
4. Policy- und Modellversion stammen aus dem DPAPI-geschützten Runtime-State.
5. Quarantäne bindet Hash, Dateiidentität und Verschiebung an dasselbe geöffnete Dateiobjekt.
6. Wiederholte Komponentenfehler führen in einen sichtbaren Audit-only Safe Mode.
