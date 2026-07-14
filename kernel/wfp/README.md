# ai_shield_wfp.sys

Product driver integration belongs here once the WDK toolchain is installed. The shared core already
defines the flow event ABI and policy decision ABI consumed by the future callout bridge.

The driver must remain a deterministic adapter:

- authorize and redirect flows through documented WFP layers;
- pend long decisions outside classify callbacks;
- validate ABI version, size, sequence, MAC and object references;
- enforce bounded queues with explicit fail policy;
- never call detection models directly in kernel mode.
