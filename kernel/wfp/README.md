# AI Shield WFP enforcement

The implemented WDK source lives in `platform/windows/wfp/driver`. It dynamically registers IPv4
and IPv6 ALE authorize, receive/accept and connect-redirect callouts and exposes bounded telemetry
through the frozen driver ABI.

The driver must remain a deterministic adapter:

- authorize, block and redirect flows through documented WFP layers;
- pend long decisions outside classify callbacks;
- validate ABI version, size, sequence, MAC and object references;
- enforce bounded queues with explicit fail policy;
- never call detection models directly in kernel mode.

Isolated file scanners are registered by the authenticated broker before resume. WFP binds the
network block to the referenced `EPROCESS`; the exact installed image path is retained as a
fail-closed fallback.
