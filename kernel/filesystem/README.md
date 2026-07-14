# AI Shield filesystem enforcement

The production source is maintained in `platform/windows/minifilter`. The WDK minifilter is no
longer a placeholder: it emits volume/file identities, protects quarantine storage, blocks image
sections from quarantined objects and maintains a bounded pending-file gate for newly written
external content.

After the first external write, new read, preview, mapping and execution opens are denied until the
registered broker returns a verdict for the same volume/file ID. Broker identity is bound to a
referenced kernel process object. A full pending table fails closed instead of evicting an older
entry. At file cleanup, Filter Manager sends a request containing a unique request ID, the
normalized NT path and the volume/file identity to the registered broker. The receive thread must
acknowledge safe queue admission within 250 ms. Content analysis then runs on a separate user-mode
worker and publishes its final decision through the broker-only verdict IOCTL. Communication,
admission and analysis errors leave the file pending; parsing never runs on the kernel I/O path.
