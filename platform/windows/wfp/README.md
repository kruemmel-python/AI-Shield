# WFP Adapter

Implements a versioned dual-stack audit and enforcement path for IPv4 and IPv6 WFP traffic.

Current contents:

- `adapter/`: CMake-built translation and fast-policy code.
- `driver/`: dynamically registers separate IPv4 and IPv6 callouts at ALE auth-connect,
  auth-receive/accept and connect-redirect. The default policy is audit-only. Redirects preserve
  the address family and target `127.0.0.1` or `::1` respectively.

The driver exposes `\\.\AIShieldWfp` with validated buffered IOCTLs. `ai_shield_kernelctl status`
reads aggregate kernel telemetry. Enforcement requires an explicit confirmation and at least one
port-scoped rule:

```powershell
ai_shield_kernelctl.exe audit
ai_shield_kernelctl.exe status
ai_shield_kernelctl.exe enforce --block-inbound 19000 --confirm-enforcement
ai_shield_kernelctl.exe enforce --redirect-port 18081 --proxy-port 18080 --exempt-pid PROXY_PID --confirm-enforcement
```

Connect redirection is intentionally restricted to one configured destination port and loopback
proxy port. Global redirection is not supported by this prototype.

The isolated content scanner is network-denied independently of the normal policy mode. The broker
registers each suspended scanner process; the callout compares the referenced `EPROCESS` and also
keeps an exact canonical installed-path check as a fail-closed fallback.
