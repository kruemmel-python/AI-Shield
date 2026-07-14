# AI Shield Microsoft driver submission staging

This directory is generated input for Microsoft signing qualification. It is not a Microsoft-signed release.

Required external gates:

1. Register the organization in the Windows Hardware Developer Program.
2. Use the current Partner Center certificate and identity requirements.
3. Run the applicable Windows HLK playlists on every declared Windows target.
4. Create and sign the HLK submission package required by Partner Center.
5. Upload through the Hardware Dashboard and download the Microsoft-signed return package.
6. Verify every returned catalog with SignTool and repeat install, reboot, HVCI and Driver Verifier qualification.

Generated locally:

- isolated INF/SYS/CAT folders for all three drivers
- matching PDB symbols and AIShieldDrivers-x64.cab
- Inf2Cat validation for: 10_X64,Server10_X64
- SHA-256 manifest: SHA256SUMS.json
- frozen ABI manifest: ABI_MANIFEST.json
- EV signed CAB: no; signing remains an external release gate

Do not enable Secure Boot for this local test-signed build. Only the returned Microsoft-trusted package may pass the production signing gate.