# Minifilter Adapter

Reserved for file identity and provenance event collection. Complex content analysis stays in userspace.

Current contents:

- `provenance_adapter.*`: CMake-built bridge into Shared Core provenance.
- `driver/`: WDK source for minifilter registration and create-path observation.
