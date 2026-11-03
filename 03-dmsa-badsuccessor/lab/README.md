# dMSA lab setup

One VMware Workstation Pro VM: Windows Server 2025 Standard Evaluation (Desktop Experience, build 26100), the only domain controller of the isolated forest `lab.local`. All changes are ordinary administrator changes to throw-away objects in `OU=LabServiceAccounts`; no exploit tool is used.

1. `2-Setup-LabDC.ps1 -Phase 1`: AD DS install and forest promotion (reboots).
2. `2-Setup-LabDC.ps1 -Phase 2`: KDS root key, "Directory Service Changes" auditing, the lab OU and auditing SACLs on the OU and the domain root.
3. `3-Test-DmsaTelemetry.ps1`: runs the test cases and exports Security 5136/5137/5141 as XML.
