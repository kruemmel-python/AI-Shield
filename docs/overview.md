# AI Shield Architecture Foundation

Der RC11-Dateipfad führt jedes neue oder veränderte Downloadobjekt zunächst über einen universellen
Magic-/Extension-/Namens-Preflight. Anschließend erhält der isolierte Minimalworker ausschließlich
das bereits gesperrte Datei-Handle. SHA-256 und Dateiidentität binden Analyse, Provenienz und
Quarantäneentscheidung; der WFP-Treiber sperrt den Worker vollständig vom IPv4-/IPv6-Netz.

Stand: 14. Juli 2026. Der zentrale Dokumentationseinstieg und die Abgrenzung von Private Desktop,
Enterprise-Betriebsprofil, Developer Full und Gateway-Prototyp stehen in
[`README.md`](README.md) und [`EDITIONEN_UND_VERSIONEN_DE.md`](EDITIONEN_UND_VERSIONEN_DE.md).

Der aktuelle Windows-Stand ergänzt den Shared Core um eine installierbare WPF-Einzelplatzedition,
Browser-Native-Messaging, DPAPI-geschützten Dateityp-Schutz, isolierte Download-Inhaltsprüfung,
Quarantäneverfahren, einen integrierten AISHAD02-Audit-Viewer sowie einen SHA-256-adressierten
Recovery-Vault mit Ransomware-Korrelation und bestätigter Rücksicherung. Die Dateisystemiteration
folgt keinen Reparse Points und ist durch einen negativen Junction-Test abgesichert.

The current codebase implements the shared, platform-neutral core required before Windows driver
integration:

- `shared/abi`: represented by `include/ai_shield/abi.hpp`.
- `shared/checked`: represented by `include/ai_shield/checked.hpp`.
- `core/policy`: represented by `include/ai_shield/policy.hpp` and `src/policy.cpp`.
- `core/audit`: represented by `include/ai_shield/audit.hpp` and `src/audit.cpp`.
  The diagnostic CLI verifies exported audit chains offline through `audit-verify`.
- `core/provenance`: represented by `include/ai_shield/provenance.hpp` and `src/provenance.cpp`.
  This includes external-file execute gating and quarantine dispositions.
- `shared/abi_validation`: represented by `include/ai_shield/abi_validation.hpp` and `src/abi_validation.cpp`.
- `core/replay`: represented by `include/ai_shield/replay.hpp`, `src/replay.cpp` and `tools/ai_shield_replay/main.cpp`.
  The replay executable accepts legacy single-payload input and the `AISHRP02` event stream used for
  Integrated Core validation.
- `prototype/http_gateway`: represented by `tools/ai_shield_prototype/main.cpp`.
  It provides the first usable usermode vertical slice: listen, analyze, block or forward HTTP requests.
- `protocols/http1`: represented by `include/ai_shield/http1.hpp` and `src/http1.cpp`.
- `protocols/dns`: represented by `include/ai_shield/dns.hpp` and `src/dns.cpp`.
- `protocols/json`: represented by `include/ai_shield/json_preflight.hpp` and `src/json_preflight.cpp`.
- `protocols/tlsmeta`: represented by `include/ai_shield/tlsmeta.hpp` and `src/tlsmeta.cpp`.
- `protocols/xml`: represented by `include/ai_shield/xml_preflight.hpp` and `src/xml_preflight.cpp`.
- `protocols/pdf`: represented by `include/ai_shield/pdf_preflight.hpp` and `src/pdf_preflight.cpp`.
- `protocols/zip`: represented by `include/ai_shield/zip_preflight.hpp` and `src/zip_preflight.cpp`.
- `protocols/pe`: represented by `include/ai_shield/pe_preflight.hpp` and `src/pe_preflight.cpp`.
- `detection/campaign`: represented by `include/ai_shield/campaign.hpp` and `src/campaign.cpp`.
- `core/service_registry`: represented by `include/ai_shield/service_registry.hpp` and `src/service_registry.cpp`.
- `core/service_discovery`: represented by `include/ai_shield/service_discovery.hpp` and `src/service_discovery.cpp`.
  Observed listeners produce proposed policies and require explicit confirmation before admission.
- `core/policy_authorization`: represented by `include/ai_shield/policy_authorization.hpp` and `src/policy_authorization.cpp`.
- `core/process_consequence`: represented by `include/ai_shield/process_consequence.hpp` and `src/process_consequence.cpp`.
  `include/ai_shield/process_guard.hpp` remains a compatibility shim and does not own Windows process sensors.
- `core/package_manifest`: represented by `include/ai_shield/package_manifest.hpp` and `src/package_manifest.cpp`.
- `core/model_registry`: represented by `include/ai_shield/model_registry.hpp` and `src/model_registry.cpp`.
- `core/policy_store`: represented by `include/ai_shield/policy_store.hpp` and `src/policy_store.cpp`.
- `core/incident_package`: represented by `include/ai_shield/incident_package.hpp` and `src/incident_package.cpp`.
- `core/update_manager`: represented by `include/ai_shield/update_manager.hpp` and `src/update_manager.cpp`.
- `core/flow_control`: represented by `include/ai_shield/flow_control.hpp` and `src/flow_control.cpp`.
- `core/worker_supervisor`: represented by `include/ai_shield/worker_supervisor.hpp` and `src/worker_supervisor.cpp`.
- `core/privacy`: represented by `include/ai_shield/privacy.hpp` and `src/privacy.cpp`.
- `core/ipc_validator`: represented by `include/ai_shield/ipc_validator.hpp` and `src/ipc_validator.cpp`.
- `core/pending_decision`: represented by `include/ai_shield/pending_decision.hpp` and `src/pending_decision.cpp`.
- `core/platform_uri`: represented by `include/ai_shield/platform_uri.hpp` and `src/platform_uri.cpp`.
- `core/retention`: represented by `include/ai_shield/retention.hpp` and `src/retention.cpp`.
- `core/response_normalizer`: represented by `include/ai_shield/response_normalizer.hpp` and `src/response_normalizer.cpp`.
- `core/risk`: represented by `include/ai_shield/risk.hpp` and `src/risk.cpp`.
- `core/fail_policy`: represented by `include/ai_shield/fail_policy.hpp` and `src/fail_policy.cpp`.
- `core/learning`: represented by `include/ai_shield/learning_mode.hpp` and `src/learning_mode.cpp`.
- `core/recovery`: represented by `include/ai_shield/recovery_plan.hpp` and `src/recovery_plan.cpp`.
- `core/release_gate`: represented by `include/ai_shield/release_gate.hpp` and `src/release_gate.cpp`.
- `core/causal_graph`: represented by `include/ai_shield/causal_graph.hpp` and `src/causal_graph.cpp`.
- `core/diagnostics`: represented by `include/ai_shield/diagnostics.hpp` and `src/diagnostics.cpp`.
- `optional/cloud_connector`: represented by `include/ai_shield/cloud_optin.hpp` and `src/cloud_optin.cpp`
  when `AI_SHIELD_ENABLE_CLOUD=ON`. The default build keeps this connector out of `ai_shield_core`.
- `core/support_package`: represented by `include/ai_shield/support_package.hpp` and `src/support_package.cpp`.
- `broker/runtime`: represented by `include/ai_shield/broker_runtime.hpp` and `src/broker_runtime.cpp`.
- `broker/backpressure`: represented by `include/ai_shield/backpressure.hpp` and `src/backpressure.cpp`.
- `core/tls_service_policy`: represented by `include/ai_shield/tls_service_policy.hpp` and `src/tls_service_policy.cpp`.
- `core/egress_gate`: represented by `include/ai_shield/egress_gate.hpp` and `src/egress_gate.cpp`.
- `core/consequence_detector`: represented by `include/ai_shield/consequence_detector.hpp` and `src/consequence_detector.cpp`.
- `detection/dataset_governance`: represented by `include/ai_shield/dataset_governance.hpp` and `src/dataset_governance.cpp`.
- `release/build_attestation`: represented by `include/ai_shield/build_attestation.hpp` and `src/build_attestation.cpp`.
- `release/fuzz_plan`: represented by `include/ai_shield/fuzz_plan.hpp` and `src/fuzz_plan.cpp`.
- `release/compatibility_lab`: represented by `include/ai_shield/compatibility_lab.hpp` and `src/compatibility_lab.cpp`.
- `protocols/http2`: represented by `include/ai_shield/http2_preflight.hpp` and `src/http2_preflight.cpp`.
- `detection/signatures`: represented by `include/ai_shield/signature_detector.hpp` and `src/signature_detector.cpp`.
- `detection/baseline`: represented by `include/ai_shield/flow_baseline.hpp` and `src/flow_baseline.cpp`.
- `detection/sequence`: represented by `include/ai_shield/sequence_model.hpp` and `src/sequence_model.cpp`.
- `detection/features`: represented by `include/ai_shield/features.hpp` and `src/features.cpp`.
- `detection/mutation`: represented by `include/ai_shield/mutation_detector.hpp` and `src/mutation_detector.cpp`.
- `detection/isolation_forest`: represented by `include/ai_shield/isolation_forest.hpp` and `src/isolation_forest.cpp`.
- `protocols/http_canonicalizer`: represented by `include/ai_shield/http_canonicalizer.hpp` and `src/http_canonicalizer.cpp`.
- `sandbox/shadow_catalog`: represented by `include/ai_shield/shadow_catalog.hpp` and `src/shadow_catalog.cpp`.
- `sandbox/budget`: represented by `include/ai_shield/sandbox_budget.hpp` and `src/sandbox_budget.cpp`.
- `core/service_identity`: represented by `include/ai_shield/service_identity.hpp` and `src/service_identity.cpp`.
- `core/system_preflight`: represented by `include/ai_shield/system_preflight.hpp` and `src/system_preflight.cpp`.
- `core/maintenance`: represented by `include/ai_shield/maintenance_mode.hpp` and `src/maintenance_mode.cpp`.
- `sandbox/result`: represented by `include/ai_shield/sandbox.hpp` and `src/sandbox.cpp`.

Windows-specific WFP, minifilter, process guard, AppContainer, Hyper-V, protected-service and installer
integration must stay outside the shared core boundary. No `HANDLE`, `NTSTATUS`, `UNICODE_STRING`, WFP
or Filter Manager type is allowed in `include/ai_shield`.

Windows milestone artifacts now live under `platform/windows`:

- `common/abi_translation`: translates platform observations into validated Shared Core ABI records.
- `service/driver_channel`: validates monotone driver-channel events and one-shot pending completions.
- `wfp/adapter`: maps telemetry-only WFP observations and fast enforcement decisions.
- `wfp/driver`: contains the telemetry-only WFP driver entry and permit-only classify callback source.
- `minifilter/provenance_adapter`: maps file events into Shared Core provenance.
- `minifilter/driver`: contains the minifilter registration source.
- `process_guard/driver`: contains the process creation sensor registration source.
- `sandbox/appcontainer_launcher`: validates and launches the shadow parser in an AppContainer profile.
