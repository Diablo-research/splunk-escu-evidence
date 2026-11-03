# Native lab results, 2026-11-01

Windows Server 2025 Standard Evaluation (build 26100) as the single DC of an isolated lab domain (lab.local), in VMware Workstation. Auditing: `Directory Service Changes` (success/failure) plus a SACL auditing Everyone Write Property, Create Child and Delete Child (inherited) on the domain root and on OU=LabServiceAccounts. Setup and test scripts are in `lab/`.

| Case | Directory changes captured (5136/5137) |
|---|---|
| negative_user_create | 5137 user (legacy0909a, legacy0909b) |
| negative_gmsa_create | 5137 msDS-GroupManagedServiceAccount (gmsa0909) |
| dmsa_create | 5137 msDS-DelegatedManagedServiceAccount (dmsa0909a) |
| negative_dmsa_description | 5136 description on dmsa0909a |
| dmsa_link_direct_write | 5136 msDS-ManagedAccountPrecededByLink on dmsa0909a -> legacy0909a. **Nothing is written on legacy0909a.** |
| dmsa_state_direct_write | 5136 msDS-DelegatedMSAState 0 removed (%%14675), 2 added (%%14674) on dmsa0909a |
| dmsa_create_for_migration | 5137 msDS-DelegatedManagedServiceAccount (dmsa0909b) |
| legit_migration_start/complete | 5136 on dmsa0909b: link to legacy0909b, state 0 -> 1. **5136 on legacy0909b:** msDS-SupersededManagedAccountLink -> dmsa0909b, msDS-SupersededServiceAccountState 1 -> 2 |

Final attribute state:
- dmsa0909a: PrecededByLink = legacy0909a, DelegatedMSAState 2. legacy0909a: **no superseded attributes**.
- dmsa0909b: PrecededByLink = legacy0909b, DelegatedMSAState 2, back-link SupersededManagedAccountLinkBL. legacy0909b: SupersededManagedAccountLink = dmsa0909b, SupersededServiceAccountState 2.

## Observations
1. **The two paths differ on the predecessor account.** Microsoft's supported migration (Start/Complete-ADServiceAccountMigration) always writes the predecessor-side link. A direct write of msDS-ManagedAccountPrecededByLink, the BadSuccessor primitive, does not. An attacker abusing BadSuccessor has no rights over the predecessor (a privileged account), so they cannot add the predecessor side.
2. **Order is not fixed.** In the legitimate migration the predecessor-side link was logged about 2 ms before the dMSA-side link, so correlation must be independent of order.
3. **OperationType values:** in Splunk, `%%14674` means value added and `%%14675` means value removed.
4. **One change was not logged:** the Complete step's final DelegatedMSAState 2 on dmsa0909b was not audited in this run, although the attribute snapshot shows it. The analytic does not depend on it.

## Splunk (lab, exact YAML searches with the filter macro expanded to `search *`)
- Windows AD dMSA Object Creation: 2 results (dmsa0909a, dmsa0909b). The gMSA and user creations did not match.
- Windows AD dMSA Predecessor Link Without Superseded Account Link: 1 result (dmsa0909a -> legacy0909a). The legitimate migration of dmsa0909b did not match.
