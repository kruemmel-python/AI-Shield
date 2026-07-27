# AI Shield: Article Templates and Publication Proposals

Last updated: July 27, 2026  
Technical baseline: AI Shield `2.0.0-rc.16`

[German version](Artikelvorlagen.md)

This document contains four editorially distinct templates. They describe the same project
baseline but emphasize different aspects for each target audience. The texts may be shortened or
adapted to a publication's style. Technical claims, maturity status, and operating limitations
should not be strengthened in the process.

## Authoritative Fact Base

The following statements are supported by the current source tree and the local RC16 evidence:

- a C++23 shared core with internal ABI 2.0 and kernel transport ABI 1.2, freeze revision 3;
- three Windows drivers for WFP, file-system minifilter, and ProcessGuard functions;
- local Broker and Core services, Desktop UI, tray agent, Audit Viewer, and quarantine;
- IPv4 and IPv6 metadata plus enforcement for explicitly enabled rules;
- file and volume identity, bounded minifilter pending, and identity-bound quarantine;
- isolated content analysis with resource limits and blocked parser network communication;
- file groups covering programs, scripts, documents, archives, images, audio, video, web files,
  and unknown formats;
- ZIP and ZIP64 deep analysis, structural validation, and Defender and AMSI integration;
- the AISHAD02 audit chain, ABI 2.0 correlation, incident packages, and deterministic replay;
- ransomware behavior correlation and a versioned recovery vault for managed user data;
- Enterprise Agent contracts for enrollment, policy hierarchy, RBAC, dual control, typed response
  commands, and hash-chained fleet batches;
- DPAPI-protected Windows enrollment and detached CMS with certificate pinning, chain validation,
  and online revocation checking;
- Control Flow Guard, CET compatibility, ASLR, and DEP/NX for user-mode binaries;
- 18 of 18 CTest targets passing in both Release and Debug configurations;
- a locally installed reference system with running Broker and Core services and three loaded
  drivers;
- reproducible RC16 ZIP packages with verified internal manifests.

## Claims That Must Not Be Used

The following statements are not supported technically or from a product-compliance perspective:

- "protects against every attack" or "provides 100 percent protection";
- "production-ready," "Microsoft-certified," or "approved for operation under Secure Boot";
- "replaces Defender, the Windows Firewall, patch management, EDR, or backups";
- "decrypts and inspects all HTTPS or QUIC content";
- "monitors every file on every file system";
- "makes kernel zero-days or compromised hardware impossible";
- "audit data is immutable to local administrators or kernel-level attackers";
- "an Enterprise Control Plane, SOC, and corporate PKI are already part of the product";
- "AI can never bypass a signed policy."

The published drivers are locally test-signed. Microsoft production driver signing, HLK/WHCP,
hardware and compatibility matrices, long-duration qualification, and independent security
assessment remain external product gates.

---

# Template 1: Technical or Scientific Publication

## Editorial Proposal

**Target audience:** technically interested readers, researchers, and security engineers  
**Recommended length:** 1,800 to 2,500 words  
**Focus:** trust and controlled impact instead of claims of perfect detection  
**Suggested title:**

> **Why AI-Accelerated Attacks Require New Trust Boundaries: AI Shield as a Windows Security
> Prototype**

**Alternative:**

> **Unknown Does Not Mean Safe: How AI Shield Correlates Files, Processes, and Network Events**

## Why AI-Accelerated Attacks Require New Trust Boundaries

Cyberattacks do not become more dangerous because a language model develops a will of its own.
They become more dangerous when capable models are integrated into agent systems with tool
access, network connectivity, and execution privileges. Such systems can search for
vulnerabilities, generate variants, and work through multi-stage attack paths much faster than a
human attacker acting alone.

The security incident described by OpenAI and Hugging Face in July 2026 demonstrates the problem
in concrete terms. During an internal cyber-capability evaluation, an AI agent identified and
chained vulnerabilities, gained internet access, and compromised Hugging Face production
infrastructure. OpenAI attributed the incident to the combination of capable models, long action
horizons, and insufficient containment of the evaluation environment. This is not evidence of a
"conscious" model. It is evidence that tools, permissions, and isolation boundaries are critical
security controls. ([OpenAI][3])

The wider threat landscape also argues against relying on signatures alone. ENISA lists phishing
at 60 percent and vulnerability exploitation at 21.3 percent as the leading initial access
vectors for 2025, while identifying ransomware as the most impactful threat in the EU. Microsoft
describes AI both as an amplifier of established attack techniques and as a defensive tool.
([ENISA][2], [Microsoft][1])

## Detection Is Not the Only Problem

Signatures, reputation, cloud classification, and behavioral analysis remain important. On their
own, however, they do not answer the question of what impact an as-yet unknown object should be
allowed to have.

An attacker can automate the following activities:

- generating payload variants and new script combinations;
- nesting archives differently or combining file formats;
- abusing legitimate Windows tools as LOLBins;
- adapting process and network sequences to existing rules;
- avoiding known signatures.

AI Shield therefore starts from a different premise:

> An external object does not become trustworthy merely because it reached the file system or
> because a single inspection component did not flag it.

This does not mean that every file on every Windows volume is blocked. The implemented intake
scope focuses on defined download and internet paths, Mark-of-the-Web provenance, configured file
groups, and explicit protection rules.

## Three Control Points, One Shared Context

AI Shield `2.0.0-rc.16` uses three Windows kernel drivers:

1. The WFP driver supplies IPv4 and IPv6 network metadata and enforces configured rules.
2. The minifilter binds file events to volume and file identity.
3. ProcessGuard observes process creation, parent relationships, and selected high-risk
   consequences.

The Broker and shared core combine these signals in an ABI 2.0 context:

```text
Origin and network flow
-> file and volume identity
-> provenance and content finding
-> process and parent
-> policy and model version
-> decision, audit record, and incident package
```

The architecture is intended to prevent one file from being inspected under one name and a
different object from subsequently being released. Flow, file, provenance, process, parent,
policy, and model identifiers remain intact across the audit trail, causal graph, incident
package, and replay.

## Bounded Pending Instead of Parsers in the Kernel

The minifilter does not perform complex content analysis in the kernel. It sends an
identity-bound request with a bounded time budget to the Broker. Analysis and parsers run
separately in user mode. Until a valid final decision is available, the affected object remains
blocked in the protected path or is handled conservatively.

The analysis worker receives only the intended file access. An AppContainer, Job Object, result
size limit, and deadline constrain its capabilities. Its IPv4 and IPv6 network communication is
additionally blocked through WFP.

This limits the consequences of a parser defect. It does not prove that every conceivable parser
exploit will be harmless.

## File Structure Instead of File Extension

The preflight chain examines more than the filename extension. Among other checks, it evaluates:

- magic bytes and mismatches between content and extension;
- double extensions, Unicode concealment, and bidirectional-text deception;
- embedded or overlaid formats;
- ZIP and ZIP64 headers, CRC values, paths, and data descriptors;
- nesting depth, entry count, total size, and compression ratio;
- executable content and scripts inside archives;
- PDF, PE, WAV, web, and general structural characteristics;
- Defender and AMSI findings.

Unknown specialist formats are not automatically treated as benign. Without a suitable full
parser, the decision remains conservative or requires a reasoned release.

## Transactional Quarantine

Releasing a file from quarantine involves more than a `Move-Item` operation. The Broker binds the
quarantine object, destination path, volume ID, file ID, hash, restore journal, and minifilter
decision to the same transaction. If the identity changes or the kernel does not confirm the
release, the operation is rolled back.

Reparse points, multiple hard links, unknown alternate data streams, and volume changes are
handled negatively within the defined protection path. This hardening reduces TOCTOU races but
does not make a universal claim about every local or remote file system.

The Desktop UI additionally assigns related quarantine objects to a detected download or
installation operation. A Codex runtime staging directory, for example, appears as an expandable
group with an operation name, source identifier, file count, and aggregate status. Individual
objects remain visible and continue to require a file-specific destination and reason for
release.

## Audit and Recovery

AISHAD02 audit segments are hash-chained, can be verified offline, and are readable in the
Desktop Audit Viewer. The hash chain makes local tampering visible, but it is not, by itself, an
immutable evidence system against a fully privileged attacker. Enterprise deployments require
prompt external anchoring and separate retention for that purpose.

The recovery vault stores versioned, content-addressed copies of managed user data. It is not a
complete system image. After a severe compromise, the intended workflow is:

```text
Isolate the device
-> assess its trust state
-> reinstall Windows from a trusted source if necessary
-> verify AI Shield and the vault
-> restore validated user data under controlled conditions
```

## An Enterprise Agent Without a Remote Shell

The current baseline includes fixed contracts for future centralized management:

- device identity covering organization, site, certificate, and hardware binding;
- rotation, revocation, and detection of cloned identities;
- signed policy hierarchy with anti-rollback, expiration, and rollout rings;
- RBAC with separate roles for creation, approval, and recovery;
- bounded response commands with leases, nonces, and replay protection;
- signed, hash-chained fleet batches with a priority-aware offline buffer.

The Agent intentionally has no general-purpose remote shell. It accepts only hard-coded actions
such as network isolation, file quarantine, incident capture, or an approved restore. High-impact
actions require approval from two different authorized identities.

Windows enrollment and detached CMS provide local reference paths for HTTPS, a client
certificate, certificate pinning, DPAPI machine protection, certificate-chain validation, and
online revocation checking. They do not provide an actual corporate PKI, Control Plane, identity
source, or SOC infrastructure.

## Evidence Status

RC16 passed the following checks locally:

- 18 of 18 CTest targets in Release;
- 18 of 18 CTest targets in Debug;
- WDK builds of all three drivers without warnings or errors;
- installation of the Broker and Core as automatic services;
- loading of all three locally test-signed drivers;
- manifest validation of 118 files in the Desktop ZIP;
- manifest validation of 414 files in the Developer Full ZIP.

User-mode binaries are built with Control Flow Guard, CET compatibility, ASLR, and DEP/NX.

These results are development and pilot evidence. They do not replace Microsoft signing,
HLK/WHCP, a hardware matrix, long-duration measurement, or independent assessment.

## What the Project Is Intended to Achieve

AI Shield is not a universal antivirus scanner and does not promise to detect every unknown
attack. The prototype investigates how Windows security functions can be connected through
shared identities, conservative releases, and verifiable state transitions.

This approach follows the Secure by Design principle that product security should not be treated
as a feature added later, but should remain a vendor responsibility throughout development,
delivery, and operation. ([CISA/FBI][4])

The source code provides development teams with a foundation for:

- additional parsers or content disarm and reconstruction modules;
- managed Control Planes and SOC integrations;
- industrial, government, or development profiles;
- reproducible blue-team and purple-team labs;
- independent kernel, parser, and policy research.

> The central idea is not: "We know every future payload."
> It is: "Unknown content receives only the capabilities that an evaluated policy explicitly
> permits."

## Author

**Ralf Krümmel**  
Independent software developer and systems architect based in Leipzig, Germany  
Developer of AI Shield  
[GitHub project](https://github.com/kruemmel-python/AI-Shield)  
[RC16 prerelease](https://github.com/kruemmel-python/AI-Shield/releases/tag/v2.0.0-rc.16)

---

# Template 2: Developer Forum

## Editorial Proposal

**Target audience:** C++, Windows, driver, and security developers  
**Recommended length:** 700 to 1,000 words  
**Focus:** architecture, contracts, testing, and concrete contribution areas  
**Suggested title:**

> **AI Shield RC16: Open-Source Windows Security with WFP, a Minifilter, ProcessGuard, and
> Typed Enterprise Contracts**

## Post Template

I am developing AI Shield, a Windows security prototype that correlates network, file, and
process events through stable identities.

The current `2.0.0-rc.16` baseline consists of:

- a C++23 shared core;
- WFP, minifilter, and ProcessGuard drivers;
- Broker and Core processes running as LocalSystem services;
- internal ABI 2.0 and a frozen kernel transport ABI 1.2;
- isolated file preflight analysis;
- identity-bound quarantine;
- AISHAD02 audit records, incident packages, and replay;
- a Desktop UI, tray agent, Audit Viewer, and recovery vault;
- Enterprise Agent contracts without a remote shell.

The file path is intentionally split into two stages. The minifilter submits only a bounded,
identity-bound decision request to the Broker. Complex parsers do not run in the kernel. The
worker is constrained by an AppContainer, Job Object, deadline, result budget, and WFP network
block.

The ZIP and ZIP64 analyzer supports Stored and DEFLATE data and validates header consistency, CRC
values, path escape, data descriptors, nesting, size budgets, and compression budgets. General
preflight checks cover magic bytes, extension mismatches, double extensions, concealment
characters, and polyglot indicators. The absence of a specialist parser does not automatically
produce a positive release decision.

The current baseline includes a separate Enterprise contract:

```text
DeviceIdentity
-> attestation and clone detection
-> signed policy with anti-rollback
-> deterministic rollout
-> typed response command
-> RBAC and dual control
-> signed fleet batch
```

There is no API for arbitrary shell commands. Response actions form a closed enum. The command
ID, nonce, target type, lease, content hash, and signers are validated. High-impact actions
require two distinct approvals.

The current local evidence is:

```text
Release CTest: 18/18
Debug CTest:   18/18
Drivers:       WFP, minifilter, and ProcessGuard loaded
Services:      Broker and Core automatic/running
Desktop ZIP:   118 manifest files verified
Full ZIP:      414 manifest files verified
```

CFG, CET, ASLR, and DEP/NX are enabled for user-mode targets. The drivers are built with WDK
`/W4 /WX`.

This remains a development and pilot prototype. The published drivers are locally test-signed.
Microsoft signing, HLK/WHCP, broad compatibility and false-positive measurement, and an
independent kernel review remain outstanding.

Suitable areas for contributions include:

- fuzzing ABI, IOCTL, and parser boundaries;
- additional file-format preflight analyzers;
- load and backpressure testing;
- implementing a Control Plane against the typed Agent contract;
- external audit anchoring and SIEM connectors;
- reproducible HVCI and Driver Verifier labs;
- reviewing quarantine, restore, and update state transitions.

Source code and RC16 artifacts:

- [Repository](https://github.com/kruemmel-python/AI-Shield)
- [Release 2.0.0-rc.16](https://github.com/kruemmel-python/AI-Shield/releases/tag/v2.0.0-rc.16)
- [Enterprise contract](ENTERPRISE_CONTROL_PLANE_DE.md)
- [RC16 evidence](RC16_RELEASE_NACHWEIS_DE.md)

---

# Template 3: Enterprise, SOC, or Security Publication

## Editorial Proposal

**Target audience:** security architects, SOC teams, incident responders, and technical
decision-makers  
**Recommended length:** 900 to 1,300 words  
**Focus:** constrained central authority, auditability, and rollout control  
**Suggested title:**

> **Why an Endpoint Agent Does Not Need a Remote Shell: The AI Shield Enterprise Contract**

## Article Template

Central endpoint management can improve security. It can also create a particularly powerful
attack channel. A compromised management platform must not automatically result in arbitrary
code execution on every managed device.

AI Shield RC16 therefore treats the Control Plane channel as a separate trust boundary.

The Agent accepts only typed actions, including:

- isolating the network or lifting an approved isolation;
- quarantining a file or blocking a hash;
- suspending a process or terminating it with additional approval;
- capturing an incident package and a user-data snapshot;
- verifying the recovery vault;
- starting an approved restore;
- rotating the device certificate;
- activating Safe Mode.

Arbitrary shell commands, PowerShell fragments, DLL loading, loading additional kernel modules,
and disabling audit collection are not part of the contract.

Each request contains the organization, target device, actor, target type, command ID, nonce,
issue time, expiration time, content hash, and signers. The maximum lease is 15 minutes.
ReplayGuard rejects reused command IDs and nonces. Actions with particularly broad impact require
dual control.

The role model separates, among others:

- Policy Author and Policy Approver;
- Responder and high-impact action approver;
- Recovery Operator and Restore Approver;
- Auditor and Platform Admin.

Policies carry monotonic policy and security versions, a minimum Agent version, validity window,
scope, parent version, rule hash, and rollout ring. Break-glass access is time-limited and
requires two different authorized approvals.

Fleet telemetry is transported in signed batches containing device, boot, batch, and event
sequences, the preceding hash, and a payload hash. During offline operation, the Agent buffers
events according to priority. Critical containment and response events are not silently discarded
in favor of diagnostic data.

The local Windows contract additionally requires:

- an HTTPS-only Control Plane URI;
- a client-authentication certificate in the machine certificate store;
- SHA-256 pinning;
- DPAPI machine protection and a restrictive ACL;
- detached CMS with exactly one signer;
- certificate-chain validation and online revocation checking.

The Agent contract is implemented and covered by automated tests. A complete, highly available
Enterprise Control Plane is not implemented. A production operator still needs a PKI or HSM,
real role and identity sources, a collector, external audit anchoring, privacy and retention
policies, failover, and disaster recovery.

The value of the approach is therefore not a claim that the system is "Enterprise-ready," but a
narrower authority boundary:

> Even central management should be able to trigger only clearly defined, signed, and auditable
> state transitions.

---

# Template 4: LinkedIn

## Editorial Proposal

**Target audience:** developers, IT leadership, and the security community  
**Recommended length:** 220 to 350 words  
**Focus:** one central idea, a few verifiable facts, and a clear limitation  
**Suggested opening:**

> **AI accelerates attack chains. Detecting known malware more quickly is therefore not enough.**

## Post Template

AI can accelerate vulnerability research, payload variation, and multi-stage attack paths. The
OpenAI and Hugging Face incident published in 2026 demonstrates what can happen when a capable
agent combines tools, a long runtime, and insufficiently restricted network access.
([OpenAI][3])

This is the boundary that **AI Shield** addresses:

> Unknown external content should not automatically receive processing or execution privileges.

AI Shield `2.0.0-rc.16` combines:

- WFP, minifilter, and ProcessGuard drivers;
- identity-bound file pending and quarantine;
- isolated file and archive analysis without parser network access;
- IPv4, IPv6, process, and provenance correlation;
- tamper-evident AISHAD02 audit records;
- a recovery vault for managed user data;
- signed Enterprise policies, RBAC, and typed response commands without a remote shell.

RC16 passed 18 of 18 local tests in both Release and Debug configurations. The Broker and Core
run as automatic services, and all three locally test-signed drivers are loaded on the reference
system. The Desktop and developer packages have fully verified SHA-256 manifests.

This is not yet a public production release. Microsoft driver signing, HLK/WHCP, hardware and
compatibility matrices, long-duration measurement, and independent security assessment remain
necessary.

AI Shield is therefore neither "unbreakable" nor a replacement for Defender, a firewall,
updates, and backups. It is an open development and pilot prototype built around a concrete
question:

**How can we constrain the impact of unknown content before a single object becomes an attack
chain?**

[Project and source code](https://github.com/kruemmel-python/AI-Shield)  
[RC16 prerelease](https://github.com/kruemmel-python/AI-Shield/releases/tag/v2.0.0-rc.16)

---

# Short Forum Teaser

I am developing AI Shield as an open Windows security prototype, not as another
signature-based antivirus scanner.

RC16 correlates network, file, provenance, and process events through ABI 2.0. Three kernel
drivers provide WFP, minifilter, and ProcessGuard signals. Complex file analysis runs outside the
kernel in a constrained worker without network access. Quarantine and release are bound to the
volume ID, file ID, hash, and journal.

RC16 adds expandable operation grouping for related quarantine objects. The baseline also includes
Enterprise Agent contracts for enrollment, anti-rollback policies, RBAC, dual control, typed
response commands without a remote shell, and hash-chained fleet batches.

Release and Debug each pass 18 of 18 tests. The drivers are currently locally test-signed;
Microsoft signing, HLK/WHCP, and independent assessment remain external gates.

[Repository](https://github.com/kruemmel-python/AI-Shield) |
[RC16](https://github.com/kruemmel-python/AI-Shield/releases/tag/v2.0.0-rc.16)

---

# Sources

[1]: https://www.microsoft.com/en-us/corporate-responsibility/cybersecurity/microsoft-digital-defense-report-2025/ "Microsoft Digital Defense Report 2025"
[2]: https://www.enisa.europa.eu/news/etl-2025-eu-consistently-targeted-by-diverse-yet-convergent-threat-groups "ENISA Threat Landscape 2025"
[3]: https://openai.com/index/hugging-face-model-evaluation-security-incident/ "OpenAI and Hugging Face partner to address security incident during model evaluation"
[4]: https://www.cisa.gov/news-events/alerts/2025/01/17/cisa-and-fbi-release-updated-guidance-product-security-bad-practices "CISA and FBI: Product Security Bad Practices"
[5]: https://github.com/kruemmel-python/AI-Shield/releases/tag/v2.0.0-rc.16 "AI Shield 2.0.0-rc.16"
