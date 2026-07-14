# Windows Platform Boundary

This tree is reserved for Windows adapters and enforcement code. Shared Core code under
`include/ai_shield` and `src` must not include Windows headers or expose Windows object types.

Only `platform/windows/common/abi_translation.cpp` may translate Windows sensor data into Shared Core
ABI records.
