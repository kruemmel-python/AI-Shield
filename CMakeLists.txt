cmake_minimum_required(VERSION 3.24)
project(ai_shield LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(AI_SHIELD_STRICT "Treat warnings as errors" ON)
option(AI_SHIELD_ENABLE_CLOUD "Build optional cloud export connector" OFF)
option(AI_SHIELD_ENABLE_WINDOWS_PLATFORM "Build Windows platform adapters" ON)

add_library(ai_shield_core
    src/abi2.cpp
    src/abi_validation.cpp
    src/audit.cpp
    src/backpressure.cpp
    src/broker_runtime.cpp
    src/build_attestation.cpp
    src/campaign.cpp
    src/compatibility_lab.cpp
    src/consequence_detector.cpp
    src/dataset_governance.cpp
    src/detection.cpp
    src/diagnostics.cpp
    src/dns.cpp
    src/fail_policy.cpp
    src/features.cpp
    src/flow_baseline.cpp
    src/flow_control.cpp
    src/egress_gate.cpp
    src/fuzz_plan.cpp
    src/http1.cpp
    src/http2_preflight.cpp
    src/http_canonicalizer.cpp
    src/ipc_validator.cpp
    src/ipv6_security.cpp
    src/json_preflight.cpp
    src/incident_package.cpp
    src/isolation_forest.cpp
    src/learning_mode.cpp
    src/maintenance_mode.cpp
    src/model_registry.cpp
    src/mutation_detector.cpp
    src/package_manifest.cpp
    src/pe_preflight.cpp
    src/policy.cpp
    src/policy_store.cpp
    src/pending_decision.cpp
    src/platform_uri.cpp
    src/process_consequence.cpp
    src/provenance.cpp
    src/privacy.cpp
    src/recovery_plan.cpp
    src/recovery_vault.cpp
    src/release_gate.cpp
    src/replay.cpp
    src/response_normalizer.cpp
    src/retention.cpp
    src/sandbox.cpp
    src/sandbox_budget.cpp
    src/service_discovery.cpp
    src/service_registry.cpp
    src/siem.cpp
    src/shadow_catalog.cpp
    src/sha256.cpp
    src/support_package.cpp
    src/sequence_model.cpp
    src/signature_detector.cpp
    src/service_identity.cpp
    src/tlsmeta.cpp
    src/health.cpp
    src/update_manager.cpp
    src/worker_supervisor.cpp
    src/xml_preflight.cpp
    src/zip_preflight.cpp
    src/pdf_preflight.cpp
    src/policy_authorization.cpp
    src/system_preflight.cpp
    src/tls_service_policy.cpp
    src/causal_graph.cpp
    src/risk.cpp
    src/ransomware.cpp
)
target_include_directories(ai_shield_core PUBLIC include)

if(AI_SHIELD_ENABLE_CLOUD)
    target_sources(ai_shield_core PRIVATE src/cloud_optin.cpp)
    target_compile_definitions(ai_shield_core PUBLIC AI_SHIELD_ENABLE_CLOUD=1)
else()
    target_compile_definitions(ai_shield_core PUBLIC AI_SHIELD_ENABLE_CLOUD=0)
endif()

if(MSVC)
    add_link_options(/Brepro "/PDBALTPATH:%_PDB%")
    target_compile_options(ai_shield_core PRIVATE /W4 /permissive- /sdl /GS)
    if(AI_SHIELD_STRICT)
        target_compile_options(ai_shield_core PRIVATE /WX)
    endif()
else()
    target_compile_options(ai_shield_core PRIVATE -Wall -Wextra -Wpedantic -Wconversion)
    if(AI_SHIELD_STRICT)
        target_compile_options(ai_shield_core PRIVATE -Werror)
    endif()
endif()

add_executable(ai_shield_diag tools/ai_shield_diag/main.cpp)
target_link_libraries(ai_shield_diag PRIVATE ai_shield_core)

add_executable(ai_shield_replay tools/ai_shield_replay/main.cpp)
target_link_libraries(ai_shield_replay PRIVATE ai_shield_core)

if(WIN32)
    add_executable(ai_shield_prototype tools/ai_shield_prototype/main.cpp)
    target_link_libraries(ai_shield_prototype PRIVATE ai_shield_core ws2_32)
    target_compile_definitions(ai_shield_prototype PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
    if(MSVC)
        target_compile_options(ai_shield_prototype PRIVATE /W4 /permissive- /sdl /GS)
    endif()

    add_executable(ai_shield_driverctl tools/ai_shield_driverctl/main.cpp)
    target_compile_definitions(ai_shield_driverctl PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
    if(MSVC)
        target_compile_options(ai_shield_driverctl PRIVATE /W4 /permissive- /sdl /GS)
    endif()

    add_executable(ai_shield_kernelctl tools/ai_shield_kernelctl/main.cpp)
    target_include_directories(ai_shield_kernelctl PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_compile_definitions(ai_shield_kernelctl PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
    if(MSVC)
        target_compile_options(ai_shield_kernelctl PRIVATE /W4 /permissive- /sdl /GS)
    endif()

    add_executable(ai_shield_broker tools/ai_shield_broker/main.cpp)
    target_include_directories(ai_shield_broker PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(ai_shield_broker PRIVATE ai_shield_core advapi32 wintrust crypt32 bcrypt)
    target_compile_definitions(ai_shield_broker PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
    if(MSVC)
        target_compile_options(ai_shield_broker PRIVATE /W4 /permissive- /sdl /GS)
        if(AI_SHIELD_STRICT)
            target_compile_options(ai_shield_broker PRIVATE /WX)
        endif()
    endif()

    add_executable(ai_shield_handle_probe tools/ai_shield_handle_probe/main.cpp)
    target_compile_definitions(ai_shield_handle_probe PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
    if(MSVC)
        target_compile_options(ai_shield_handle_probe PRIVATE /W4 /permissive- /sdl /GS)
    endif()

    add_executable(ai_shield_service tools/ai_shield_service/main.cpp)
    target_include_directories(ai_shield_service PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(ai_shield_service PRIVATE advapi32)
    target_compile_definitions(ai_shield_service PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
    if(MSVC)
        target_compile_options(ai_shield_service PRIVATE /W4 /permissive- /sdl /GS)
    endif()
endif()

add_executable(ai_shield_unit_tests tests/unit/main.cpp)
target_link_libraries(ai_shield_unit_tests PRIVATE ai_shield_core)

enable_testing()
add_test(NAME ai_shield_unit_tests COMMAND ai_shield_unit_tests)

if(WIN32 AND AI_SHIELD_ENABLE_WINDOWS_PLATFORM)
    add_library(ai_shield_windows_platform
        platform/windows/common/abi_translation.cpp
        platform/windows/service/driver_channel.cpp
        platform/windows/wfp/adapter/wfp_telemetry.cpp
        platform/windows/wfp/adapter/wfp_enforcement.cpp
        platform/windows/sandbox/appcontainer_launcher.cpp
        platform/windows/sandbox/parser_pool.cpp
        platform/windows/minifilter/provenance_adapter.cpp
        platform/windows/security/secure_runtime_state.cpp
        platform/windows/security/tpm_trust_anchor.cpp
        platform/windows/sensors/etw_amsi_adapter.cpp
        platform/windows/siem/syslog_connector.cpp
    )
    target_include_directories(ai_shield_windows_platform PUBLIC include ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(ai_shield_windows_platform PUBLIC ai_shield_core userenv crypt32 bcrypt ncrypt amsi ole32 advapi32 ws2_32)
    target_link_libraries(ai_shield_broker PRIVATE ai_shield_windows_platform)
    target_compile_definitions(ai_shield_windows_platform PUBLIC WIN32_LEAN_AND_MEAN NOMINMAX)
    if(MSVC)
        target_compile_options(ai_shield_windows_platform PRIVATE /W4 /permissive- /sdl /GS /wd4324)
        if(AI_SHIELD_STRICT)
            target_compile_options(ai_shield_windows_platform PRIVATE /WX)
        endif()
    endif()

    add_executable(ai_shield_windows_platform_tests tests/windows_platform/main.cpp)
    target_link_libraries(ai_shield_windows_platform_tests PRIVATE ai_shield_windows_platform)
    add_test(NAME ai_shield_windows_platform_tests COMMAND ai_shield_windows_platform_tests)

    add_executable(ai_shield_integrations tools/ai_shield_integrations/main.cpp)
    target_link_libraries(ai_shield_integrations PRIVATE ai_shield_windows_platform)
    if(MSVC)
        target_compile_options(ai_shield_integrations PRIVATE /W4 /permissive- /sdl /GS)
    endif()
endif()

if(WIN32)
    add_test(NAME ai_shield_prototype_self_test COMMAND ai_shield_prototype --self-test)
    add_test(NAME ai_shield_driverctl_self_test COMMAND ai_shield_driverctl self-test)
    add_test(NAME ai_shield_kernelctl_self_test COMMAND ai_shield_kernelctl self-test)
    add_test(NAME ai_shield_broker_self_test COMMAND ai_shield_broker self-test)
    add_test(NAME ai_shield_handle_probe_self_test COMMAND ai_shield_handle_probe self-test)
    add_test(NAME ai_shield_service_self_test COMMAND ai_shield_service self-test)
    add_test(NAME ai_shield_driverctl_status COMMAND ai_shield_driverctl status)
    add_test(NAME ai_shield_integrations_self_test COMMAND ai_shield_integrations self-test)

    add_executable(ai_shield_browser_host tools/ai_shield_browser_host/main.cpp)
    if(MSVC)
        target_compile_options(ai_shield_browser_host PRIVATE /W4 /WX /permissive- /sdl /GS)
    endif()
    add_test(NAME ai_shield_browser_host_self_test COMMAND ai_shield_browser_host self-test)
    add_test(NAME ai_shield_ransomware_recovery_test
        COMMAND powershell.exe -NoProfile -ExecutionPolicy Bypass -File
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/windows_ransomware_recovery.ps1
        -RepositoryRoot ${CMAKE_CURRENT_SOURCE_DIR})
endif()
