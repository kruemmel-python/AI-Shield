# ADR 0001: Shared Core Boundary

Status: Accepted, am 13. Juli 2026 erneut bestätigt

## Decision

The shared core exposes only C++ fixed-width integer, byte-array and standard-layout records across
security boundaries.

## Rationale

The development plan requires Linux portability and treats Windows APIs as evidence rather than a root
of trust. Keeping Windows types outside the shared core makes ABI validation, fuzzing and future platform
adapters practical.

## Consequences

Driver and Win32 implementations must translate platform-native objects into validated ABI records before
calling policy, audit, detection or provenance code.
