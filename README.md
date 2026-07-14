# AI Shield

Die getrennte Ausgabe für private Windows-Einzelplatzrechner liegt unter
[`editions/private_desktop`](editions/private_desktop). Sie besitzt eigene Installations-, Start-,
Status-, Stopp- und Deinstallationspfade sowie eine ausschließlich auf private Endanwender bezogene
Softwarebewertung. Das Binärpaket wird mit `tools/package_private_desktop.ps1` erzeugt.

Die vollständige deutschsprachige Anleitung für Architektur, Build, Secure Boot, Testsigning,
Treiberinstallation und den End-to-End-Prototypstart steht in
[`docs/PROTOTYP_HANDBUCH_DE.md`](docs/PROTOTYP_HANDBUCH_DE.md).

Das deutschsprachige Whitepaper zu Zweck, Schutzmodell, aktueller Windows-Bedrohungslage und
Produktvision steht in [`docs/WHITEPAPER_DE.md`](docs/WHITEPAPER_DE.md).

Eine evidenzbasierte Einordnung von Funktionsumfang, Schutzwirkung und Produktreife steht in
[`Softwarebewertung.md`](Softwarebewertung.md).

Der Einstieg für neue Entwicklungsteams steht in
[`docs/ENTWICKLER_SCHNELLSTART_DE.md`](docs/ENTWICKLER_SCHNELLSTART_DE.md). Offen gebliebene
Produktfunktionen und externe Release-Gates werden in
[`docs/FEHLENDE_FUNKTIONEN_DE.md`](docs/FEHLENDE_FUNKTIONEN_DE.md) geführt.

Ausführbare Last-, Missbrauchs-, Installations-, Neustart- und Recovery-Gates sowie die Vorbereitung
der Microsoft-Treibersignierung beschreibt
[`docs/PRODUKTQUALIFIKATION_DE.md`](docs/PRODUKTQUALIFIKATION_DE.md).

Der eingefrorene Treiber-ABI-Vertrag und die Übergabe an ein separates HLK-Labor stehen in
[`docs/ABI_FREEZE_UND_HLK_DE.md`](docs/ABI_FREEZE_UND_HLK_DE.md).
Der interne ABI-2.0-Vertrag, seine HMAC-Prüfung und die kompatible Übersetzung vom
Treiber-ABI 1.2 sind in [`docs/ABI_2_0_DE.md`](docs/ABI_2_0_DE.md) dokumentiert. Der systemweite
IPv4-/IPv6-Netzwerkschutz und seine Grenzen sind in [`docs/NETZWERKSCHUTZ_DE.md`](docs/NETZWERKSCHUTZ_DE.md) beschrieben.
Die automatische, nicht-invasive Windows-Sicherheitspruefung ist in
[`docs/WINDOWS_HARDENING_DE.md`](docs/WINDOWS_HARDENING_DE.md) beschrieben.
Browser-Sensor, WEF-Zielpin, WDAC-Audit, datensparsames PowerShell-Logging, Firewall-Transaktion,
UAC-Assistent und ASR-Evidenz sind in
[`docs/ENTERPRISE_SECURITY_INTEGRATIONS_DE.md`](docs/ENTERPRISE_SECURITY_INTEGRATIONS_DE.md) dokumentiert.
Eine schrittweise Anleitung fuer Juniorentwickler steht in
[`docs/JUNIOR_ENTERPRISE_INTEGRATION_SCHNELLSTART_DE.md`](docs/JUNIOR_ENTERPRISE_INTEGRATION_SCHNELLSTART_DE.md).
Der aktuelle Aktivierungsstand und die noch benoetigten externen Werte stehen in
[`docs/SICHERHEITSABSCHLUSS_DE.md`](docs/SICHERHEITSABSCHLUSS_DE.md).
Der zuletzt verifizierte Build-, Signatur- und Installationsstand steht in
[`docs/AKTUELLER_INSTALLATIONSSTAND_DE.md`](docs/AKTUELLER_INSTALLATIONSSTAND_DE.md).
Eine kompakte Systemdarstellung steht in
[`docs/ARCHITEKTUR_WHITEBOARD_DE.md`](docs/ARCHITEKTUR_WHITEBOARD_DE.md).
ETW/AMSI, IPv6/QUIC, Parserpool, TPM, SIEM und SOC-Konsole beschreibt
[`docs/SCHUTZABDECKUNG_2_0_DE.md`](docs/SCHUTZABDECKUNG_2_0_DE.md).

Ein-Klick-Prototypstart unter Windows:

- `AI_Shield_Start.cmd` startet Treiber und Gateway für ein Backend auf `127.0.0.1:18081`.
- `AI_Shield_Start_Demo.cmd` startet Treiber und den integrierten Demo-Modus.
- `AI_Shield_Stop.cmd` beendet Gateway und Treiber.

Der Start richtet bei Bedarf eine lokal RSA-signierte Policy ein, aktiviert sie mit monotoner
Security-Version und startet den `LocalSystem`-Dienst `AIShieldBroker`. Der Broker persistiert
sequenzierte Kernelereignisse unter `C:\ProgramData\AIShield\audit`. Policyzustand und Rollback-
Slots liegen unter `C:\ProgramData\AIShield\policy`.

Der Ein-Klick-Backendmodus aktiviert eine portgebundene, transparente IPv4-/IPv6-WFP-Umleitung von
Backend-Port 18081 zum geschützten Listener 18080. Andere Ports und Protokolle werden nicht
automatisch umgeleitet.

This repository is the C++23 implementation foundation for the AI Shield development plan in
`AI_Shield_Vollstaendiger_Entwicklungsplan.docx`.

Implemented in this foundation:

- Standard-layout ABI records for flow events and policy decisions.
- Checked arithmetic and explicit result/status handling.
- Flow state machine with invalid-transition rejection.
- HTTP/1, DNS and JSON preflight for malformed, ambiguous and over-budget inputs.
- TLS metadata, XML, PDF, ZIP and PE preflight for downgrade, entity, active-content, archive and executable risks.
- Deterministic detection evidence and policy decisions.
- SHA-256 backed evidence hashes and append-only audit hash chain.
- Deterministic audit export/import plus offline `ai_shield_diag audit-verify` validation.
- File provenance store semantics for external execution pending and verdict invalidation.
- Bounded adapter queue primitive and sensor health degradation assessment.
- Service registry admission control, sandbox result handling and process consequence guard.
- Package manifest trust gate for ABI compatibility, monotone security versions and signer fingerprint checks.
- Archive provenance propagation and A/B update activation with rollback on failed boot health.
- Campaign and adaptive mutation correlation for distributed probing patterns.
- UDP/session limiting, token bucket rate control and proxy redirect loop detection.
- Parser worker crash isolation and privacy-preserving export sanitization.
- Immutable production model registry with online-learning rejection.
- Transactional policy store with rollback and privacy-preserving incident package generation.
- IPC flow event validation with ABI, sequence, time-window and keyed MAC checks.
- Pending decision timeout handling for asynchronous enforcement paths.
- Platform-neutral file URI normalization, retention decisions and external response normalization.
- Plan-aligned risk score bands, service fail-policy matrix, health aggregation and causal chain graph.
- Diagnostics snapshot degradation checks for operations/UI surfaces.
- Signature detection, robust flow baselines, N-gram sequence novelty and feature extraction.
- HTTP request canonicalization for stable parser/detection input.
- SimHash mutation detection, deterministic isolation-forest scoring, shadow-target routing and sandbox budgets.
- Service certificate pinning metadata for managed endpoints.
- Service discovery proposals with explicit confirmation before admission.
- Policy change authorization for admin and high-risk local confirmation gates.
- Quarantine and execute-gate semantics for external file provenance.
- Installer-facing system preflight and maintenance-mode uninstall/audit guards.
- Learning-mode enforcement with a 14-day cap and active hard-rule handling.
- Cloud transfer opt-in gates, support manifest hashing and recovery action plans.
- Release-gate checks for soak, corpus, false-block, campaign, performance and recovery metrics.
- Broker worker sizing, multi-level backpressure and managed TLS endpoint gates.
- Dataset governance, canary promotion checks and reproducible build attestation.
- HTTP/2 frame preflight, egress gating and runtime consequence detection.
- Parser corpus readiness and compatibility lab gate evaluation.
- Integrated Core replay path through parser, features, signatures, policy, audit and causal graph.
- Shared Core ABI validation, audit checkpoints, provenance copy/rename chains and bounded pending decisions.
- Windows platform adapter tree and Shared Core boundary scan.
- Windows platform adapters for WFP telemetry/enforcement, driver-channel validation,
  AppContainer shadow parser launch validation and Minifilter provenance events.
- WDK driver entry sources for telemetry-only WFP, Minifilter provenance observation and process sensor wiring.
- Dual-stack WFP callouts and transparent IPv4/IPv6 redirect enforcement.
- Bounded sequenced WFP, Minifilter and ProcessGuard event queues with a persistent LocalSystem broker.
- RSA-signed monotone Windows policies with staged activation, replay rejection and verified rollback.
- Automatic MOTW provenance classification, Authenticode trust checks and transactional SHA-256 quarantine.
- Configurable ProcessGuard gates for user-temp execution, downloads, risky script/LOLBin commands and Office child processes.
- HVCI state collection plus explicitly armed Driver Verifier and reboot laboratory workflows.
- Driver installation manager and INF package metadata for prototype driver services.
- Usable HTTP gateway prototype for local end-to-end request protection.
- Diagnostic CLI and unit tests.
- Internal ABI 2.0 sensor records with fixed layouts, deterministic HMAC-SHA-256 authentication and
  validated translation from the frozen kernel transport ABI 1.2.
- AppContainer parser launch with Job Object process-count, memory and lifecycle limits.
- Correlated `AISHAD02` audit records preserving ABI 2.0 object identity through incident and replay.
- DPAPI machine-protected runtime state with key rotation, legacy migration and recovery slot.
- TOCTOU-resistant same-volume quarantine by locked file handle and stable file/volume identity.
- `AIShieldCore` LocalSystem supervision with bounded restart backoff, audit-only Safe Mode and health state.
- Elevated local administration for health, key rotation, quarantine release, audit export and recovery.
- Detached-CMS and Authenticode verified A/B binary update activation with rollback.
- Confirmation-gated uninstall and executable recovery-drill workflows.
- ABI-2.0 ETW and AMSI sensor adapters with bounded AMSI scanning.
- IPv6 extension-chain, fragmentation, ICMPv6 and QUIC long-header metadata validation.
- Credential-access and persistence ProcessGuard rules with enforcement counters.
- Bounded AppContainer parser pool with local result pipe and deadline termination.
- Optional Microsoft Platform Crypto Provider TPM anchor and challenge signatures.
- JSON Lines, CEF and LEEF formatting plus dual-stack UDP/TCP syslog transport.
- Elevated loopback-only SOC console for health, Safe Mode and quarantine workflows.

Create a clean source package for another development team:

```powershell
powershell -ExecutionPolicy Bypass -File tools\package_developer_release.ps1
```

Build:

```powershell
$CMAKE_EXE = "C:\Program Files\CMake\bin\cmake.exe"
$CTEST_EXE = "C:\Program Files\CMake\bin\ctest.exe"
& $CMAKE_EXE -S . -B build_vs -G "Visual Studio 17 2022" -A x64
& $CMAKE_EXE --build build_vs --config Release --parallel
& $CTEST_EXE --test-dir build_vs -C Release --output-on-failure
```

Optional cloud export connector:

```powershell
& $CMAKE_EXE -S . -B build_vs_cloud -G "Visual Studio 17 2022" -A x64 -DAI_SHIELD_ENABLE_CLOUD=ON
```

Windows platform adapters are enabled by default on Windows:

```powershell
& $CMAKE_EXE -S . -B build_vs -G "Visual Studio 17 2022" -A x64 -DAI_SHIELD_ENABLE_WINDOWS_PLATFORM=ON
```

WDK driver sources live under `platform/windows/*/driver`. They are intentionally separate from the
normal CMake build because signing, INF packaging and driver verifier/HLK configuration belong to the
WDK pipeline.

Build prototype drivers:

```powershell
powershell -ExecutionPolicy Bypass -File platform\windows\build_drivers.ps1 -Configuration Release
```

Vollständiger administrativer Neuaufbau und Austausch des lokalen Prototyps:

```powershell
powershell -ExecutionPolicy Bypass -File platform\windows\installer\deploy_current_prototype.ps1
```

Test-sign the prototype drivers. Run these commands from an elevated PowerShell; reboot after enabling
Windows test-signing mode:

```powershell
Set-Location D:\AI_Shield
powershell -ExecutionPolicy Bypass -File platform\windows\installer\enable_testsigning.ps1 -State on
powershell -ExecutionPolicy Bypass -File platform\windows\installer\sign_driver_package.ps1 -PackageDir driver_package\Release
Restart-Computer
```

If `bcdedit` reports that the value is protected by Secure Boot, local test-signed kernel drivers cannot
be loaded on that boot configuration. Disable Secure Boot in UEFI firmware for prototype testing, run
`enable_testsigning.ps1 -State on` again, reboot, then install the drivers. `StartService failed error=577`
means Windows rejected the kernel driver signature under the current boot policy.

Driver control prototype:

```powershell
build_vs\Release\ai_shield_driverctl.exe status
build_vs\Release\ai_shield_driverctl.exe install --wfp D:\AI_Shield\driver_package\Release\AIShieldWfp.sys --minifilter D:\AI_Shield\driver_package\Release\AIShieldMiniFilter.sys --process D:\AI_Shield\driver_package\Release\AIShieldProcessGuard.sys
build_vs\Release\ai_shield_driverctl.exe start
build_vs\Release\ai_shield_driverctl.exe stop
build_vs\Release\ai_shield_driverctl.exe uninstall
```

`install`, `start`, `stop` and `uninstall` require an elevated PowerShell. The INF package metadata lives in
`platform/windows/installer`.

The three WDK projects produce installable `.sys` files. The package includes `.inf` metadata and
local test-signing automation. Production distribution still requires catalog generation,
Microsoft-compatible signing and the corresponding release qualification.

Signed policy status from an elevated PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File platform\windows\policy\ai_shield_policy.ps1 -Action status
Get-Service AIShieldBroker
```

Example:

```powershell
"GET /../../boot.ini HTTP/1.1`r`nHost: local`r`n`r`n" | build\ai_shield_diag.exe
```

Audit verification:

```powershell
build_vs\Release\ai_shield_diag.exe audit-verify path\to\audit.bin
```

Replay:

```powershell
build_vs\Release\ai_shield_replay.exe path\to\scenario.bin
```

Replay scenario formats:

- `AISHRPLY`: legacy single-payload scenario.
- `AISHRP02`: event-stream scenario with `FlowOpen`, `FlowData`, `ServiceIdentity`,
  `ProtocolHint`, `ProcessEvidence`, `FileEvidence` and `FlowClose` records.

Prototype gateway:

```powershell
build_vs\Release\ai_shield_prototype.exe --listen 127.0.0.1:18080 --demo
```

Try it from another shell:

```powershell
curl.exe http://127.0.0.1:18080/safe
curl.exe --path-as-is http://127.0.0.1:18080/../../secret
```

To protect a local backend:

```powershell
build_vs\Release\ai_shield_prototype.exe --listen 127.0.0.1:18080 --backend 127.0.0.1:8080
```

## Lizenz und Urheber

AI Shield ist unter der [Apache License, Version 2.0](LICENSE) veröffentlicht.

Copyright 2026 Ralf Krümmel. Entwickelt von Ralf Krümmel,
Wintergartenstraße, Leipzig, Deutschland. Weitere Angaben stehen in [NOTICE](NOTICE).
