# Minifilter Adapter

Implements file identity, provenance telemetry and kernel enforcement. Complex content analysis
stays in an isolated user-mode process.

Current contents:

- `provenance_adapter.*`: CMake-built bridge into Shared Core provenance.
- `driver/`: WDK source for volume/file-ID telemetry, quarantine execution blocking and the
  pending-file read/preview gate. Broker registration and verdict updates use administrator/SYSTEM-
  only IOCTLs and referenced kernel process identities.

## Bounded handoff and asynchronous analysis protocol

After an external write reaches cleanup, the driver sends an `AI_SHIELD_FILE_ANALYSIS_REQUEST`
through `\AIShieldMinifilterPort`. The fixed-size request contains protocol version, request ID,
volume ID, file ID and the normalized NT path. Only the already registered broker process may
connect, and only one client is accepted.

The receive thread validates and queues the request, then returns a matching
`AI_SHIELD_FILE_PENDING` acknowledgement within the driver's 250 ms deadline. A separate analysis
worker reopens the path without following a reparse point, verifies volume/file identity, link
count and stream set, hashes and scans the locked handle, and submits the final verdict through the
broker-only IOCTL. A missing broker, timeout, malformed response, queue exhaustion or analysis
failure never releases the entry; subsequent read, preview, mapping and execution attempts remain
denied. The periodic directory scan remains a serialized recovery path, not the primary channel.
