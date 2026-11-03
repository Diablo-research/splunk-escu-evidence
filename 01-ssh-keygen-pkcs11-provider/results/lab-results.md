# Native bypass replay, 2026-11-01

Host: Windows x64, OpenSSH 9.5.6.2 (System32\OpenSSH), Sysmon 15.22. Script: `Test-Pkcs11Bypass.ps1` (run bypass-20261101-003036).
Provider: the benign `provider-marker.dll` (see `provider-marker.c`), copied as evil.dll and signed.dll. User and host names are anonymized below (LabUser, WIN-PKCS11-LAB).

## Windows results
All 9 variants ran the provider callback (marker file created, exit 255). Every variant logged the same canonical ImageLoaded path.

| Case | Command-line argument | Callback | Signed / SignatureStatus |
|---|---|---|---|
| baseline_absolute | `-D "C:\Users\LabUser\...\evil.dll"` | yes | false / Unavailable |
| relative_dot | `-D .\evil.dll` | yes | false / Unavailable |
| bare_name_cwd | `-D evil.dll` | yes | false / Unavailable |
| no_extension | `-D evil` | yes | false / Unavailable |
| forward_slashes | `-D "C:/Users/LabUser/.../evil.dll"` | yes | false / Unavailable |
| dot_dot_segment | `-D "...\sub\..\evil.dll"` | yes | false / Unavailable |
| cluster_qD | `-qD "...\evil.dll"` | yes | false / Unavailable |
| cluster_vvvD | `-vvvD "...\evil.dll"` | yes | false / Unavailable |
| self_signed | `-D "...\signed.dll"` | yes | false / Unavailable |

`Get-AuthenticodeSignature signed.dll`: Status UnknownError, SignerCertificate CN=PKCS11 Lab Self-Signed (self-issued). So the file really is signed, and Sysmon still reports `Signed=false` for an untrusted signature.

## Splunk results (lab, index pkcs11_bypass, 292 events: 9 x EID 1, 283 x EID 7)
- v0 search (exact `-D` path equality, Users only): **2 of 9**. It caught only the two absolute-path runs (evil.dll, signed.dll).
- Revised search (image load outside Windows/Program Files, unsigned or untrusted; command line attached for context): **9 of 9**.

