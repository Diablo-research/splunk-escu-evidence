# dMSA (BadSuccessor) abuse via predecessor link without superseded-account link

Proposal: splunk/security_content#4384

**Technique.** BadSuccessor (CVE-2025-53779): a user who can create a delegated Managed Service Account (dMSA) in any OU writes `msDS-ManagedAccountPrecededByLink` to point at a privileged account and sets `msDS-DelegatedMSAState=2`. The dMSA then inherits the target's privileges. No permission over the target account is needed.

**Lab.** VM B in [LAB.md](../LAB.md): Windows Server 2025 Standard Evaluation (build 26100), the single domain controller of the isolated domain `lab.local`. Auditing: "Directory Service Changes" (success/failure) plus a SACL auditing Everyone Write Property / Create Child / Delete Child on the domain root and `OU=LabServiceAccounts`. Setup and test scripts are in `lab/`. All objects are throw-away lab objects.

**Dataset.** `data/windows-events.log`: 49 Security events (EID 5136: 44, EID 5137: 5). sha256 `d55c7fdbd84d89bc0c8ab849e04dcd2f4973e1d9fbd5b224fc1b368f8600113c`.

## Test cases
| Case | What was done | Expected |
|---|---|---|
| negative_user_create | create users legacy0909a, legacy0909b | no result |
| negative_gmsa_create | create gMSA gmsa0909 | no result |
| dmsa_create | create dMSA dmsa0909a | Object Creation |
| negative_dmsa_description | change dmsa0909a description | no result |
| dmsa_link_direct_write + state | write PrecededByLink on dmsa0909a -> legacy0909a, DelegatedMSAState=2 (the BadSuccessor pattern) | **Link Without Superseded** |
| dmsa_create_for_migration | create dMSA dmsa0909b | Object Creation |
| legit_migration_start/complete | Microsoft `Start-/Complete-ADServiceAccountMigration` dmsa0909b <- legacy0909b | no link result |

## Proposed detections
| Detection | Type | Data source | Expected results on this dataset |
|---|---|---|---|
| [Windows AD dMSA Object Creation](detections/windows_ad_dmsa_object_creation.yml) | Anomaly | Windows Event Log Security 5137 | 2 |
| [Windows AD dMSA Predecessor Link Without Superseded Account Link](detections/windows_ad_dmsa_predecessor_link_without_superseded_account_link.yml) | TTP | Windows Event Log Security 5136 | 1 |

## What the data shows
- **Microsoft's supported migration writes both sides; the attack writes one.** The migration logs 5136 on the dMSA (PrecededByLink) and on the predecessor (`msDS-SupersededManagedAccountLink` -> the dMSA, `msDS-SupersededServiceAccountState`). The direct write logs nothing on the predecessor. An attacker abusing BadSuccessor has no rights over the predecessor, so they cannot add that side.
- In the migration the predecessor-side link was logged about 2 ms *before* the dMSA-side link, so the correlation does not depend on order.
- `OperationType` is `%%14674` (value added) / `%%14675` (value removed) in Splunk.
- The comparison search (alert on any PrecededByLink write) returns both the attack and the legitimate migration.

## Results
- Splunk replay of this dataset: [`results/splunk-replay.md`](results/splunk-replay.md).
- Native lab notes, including the attribute snapshot after each path: [`results/lab-results.md`](results/lab-results.md).

## Sample events
<details><summary>5136: PrecededByLink written on dmsa0909a (attack-style direct write)</summary>

```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}"/>
    <EventID>5136</EventID>
    <Version>0</Version>
    <Level>0</Level>
    <Task>14081</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8020000000000000</Keywords>
    <TimeCreated SystemTime="2026-11-01T17:09:32.2223656Z"/>
    <EventRecordID>2374</EventRecordID>
    <Correlation/>
    <Execution ProcessID="784" ThreadID="900"/>
    <Channel>Security</Channel>
    <Computer>WIN-9FBIF1KHFAH.lab.local</Computer>
    <Security/>
  </System>
  <EventData>
    <Data Name="OpCorrelationID">{edfe70fe-a4d0-460d-b1e3-4372202b8d2a}</Data>
    <Data Name="AppCorrelationID">-</Data>
    <Data Name="SubjectUserSid">S-1-5-21-1000000000-2000000000-3000000000-500</Data>
    <Data Name="SubjectUserName">Administrator</Data>
    <Data Name="SubjectDomainName">LAB</Data>
    <Data Name="SubjectLogonId">0x9d48b</Data>
    <Data Name="DSName">lab.local</Data>
    <Data Name="DSType">%%14676</Data>
    <Data Name="ObjectDN">CN=dmsa0909a,OU=LabServiceAccounts,DC=lab,DC=local</Data>
    <Data Name="ObjectGUID">{0ff68b58-b01c-493e-baa3-323e18212708}</Data>
    <Data Name="ObjectClass">msDS-DelegatedManagedServiceAccount</Data>
    <Data Name="AttributeLDAPDisplayName">msDS-ManagedAccountPrecededByLink</Data>
    <Data Name="AttributeSyntaxOID">2.5.5.1</Data>
    <Data Name="AttributeValue">CN=legacy0909a,OU=LabServiceAccounts,DC=lab,DC=local</Data>
    <Data Name="OperationType">%%14674</Data>
  </EventData>
</Event>
```
</details>

<details><summary>5136: PrecededByLink written on dmsa0909b (Microsoft migration)</summary>

```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}"/>
    <EventID>5136</EventID>
    <Version>0</Version>
    <Level>0</Level>
    <Task>14081</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8020000000000000</Keywords>
    <TimeCreated SystemTime="2026-11-01T17:09:42.2480147Z"/>
    <EventRecordID>2406</EventRecordID>
    <Correlation/>
    <Execution ProcessID="784" ThreadID="900"/>
    <Channel>Security</Channel>
    <Computer>WIN-9FBIF1KHFAH.lab.local</Computer>
    <Security/>
  </System>
  <EventData>
    <Data Name="OpCorrelationID">{87fb6c28-a6ff-4f01-a639-29ac4e9ae187}</Data>
    <Data Name="AppCorrelationID">-</Data>
    <Data Name="SubjectUserSid">S-1-5-21-1000000000-2000000000-3000000000-500</Data>
    <Data Name="SubjectUserName">Administrator</Data>
    <Data Name="SubjectDomainName">LAB</Data>
    <Data Name="SubjectLogonId">0x9d48b</Data>
    <Data Name="DSName">lab.local</Data>
    <Data Name="DSType">%%14676</Data>
    <Data Name="ObjectDN">CN=dmsa0909b,OU=LabServiceAccounts,DC=lab,DC=local</Data>
    <Data Name="ObjectGUID">{8f10812c-30e4-45b7-8943-78430c8db18c}</Data>
    <Data Name="ObjectClass">msDS-DelegatedManagedServiceAccount</Data>
    <Data Name="AttributeLDAPDisplayName">msDS-ManagedAccountPrecededByLink</Data>
    <Data Name="AttributeSyntaxOID">2.5.5.1</Data>
    <Data Name="AttributeValue">CN=legacy0909b,OU=LabServiceAccounts,DC=lab,DC=local</Data>
    <Data Name="OperationType">%%14674</Data>
  </EventData>
</Event>
```
</details>

<details><summary>5136: SupersededManagedAccountLink written on legacy0909b (only in the migration)</summary>

```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}"/>
    <EventID>5136</EventID>
    <Version>0</Version>
    <Level>0</Level>
    <Task>14081</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8020000000000000</Keywords>
    <TimeCreated SystemTime="2026-11-01T17:09:42.2467864Z"/>
    <EventRecordID>2403</EventRecordID>
    <Correlation/>
    <Execution ProcessID="784" ThreadID="900"/>
    <Channel>Security</Channel>
    <Computer>WIN-9FBIF1KHFAH.lab.local</Computer>
    <Security/>
  </System>
  <EventData>
    <Data Name="OpCorrelationID">{87fb6c28-a6ff-4f01-a639-29ac4e9ae187}</Data>
    <Data Name="AppCorrelationID">-</Data>
    <Data Name="SubjectUserSid">S-1-5-21-1000000000-2000000000-3000000000-500</Data>
    <Data Name="SubjectUserName">Administrator</Data>
    <Data Name="SubjectDomainName">LAB</Data>
    <Data Name="SubjectLogonId">0x9d48b</Data>
    <Data Name="DSName">lab.local</Data>
    <Data Name="DSType">%%14676</Data>
    <Data Name="ObjectDN">CN=legacy0909b,OU=LabServiceAccounts,DC=lab,DC=local</Data>
    <Data Name="ObjectGUID">{8dab6e02-47c7-4565-83ef-35ee238120a9}</Data>
    <Data Name="ObjectClass">user</Data>
    <Data Name="AttributeLDAPDisplayName">msDS-SupersededManagedAccountLink</Data>
    <Data Name="AttributeSyntaxOID">2.5.5.1</Data>
    <Data Name="AttributeValue">CN=dmsa0909b,OU=LabServiceAccounts,DC=lab,DC=local</Data>
    <Data Name="OperationType">%%14674</Data>
  </EventData>
</Event>
```
</details>

## Limits
- Needs Directory Service Changes auditing with a SACL covering dMSA objects and accounts that can be superseded; neither is on by default.
- Single DC, one migration and one attack pair. Larger environments may log the two sides on different DCs; the correlation is by DN, not by host.
- Requires Windows Server 2025 domain controllers (dMSA does not exist earlier).

## Reproduce
- **Replay the dataset in any Splunk with ESCU and the Sysmon / Windows TA:** load `data/windows-events.log` with sourcetype `XmlWinEventLog` and source `XmlWinEventLog:Security`, then run the YAML searches with the filter macro removed. `tools/replay.py` does exactly this and writes `results/splunk-replay.md`.
- **Regenerate the dataset:** run the capture script in `lab/` on the machine described in [LAB.md](../LAB.md).

## Files
- `data/windows-events.log`
- `detections/windows_ad_dmsa_object_creation.yml`
- `detections/windows_ad_dmsa_predecessor_link_without_superseded_account_link.yml`
- `lab/2-Setup-LabDC.ps1`
- `lab/3-Test-DmsaTelemetry.ps1`
- `lab/README.md`
- `results/lab-results.md`
- `results/splunk-replay.md`, `results/splunk-replay.json` (written by `tools/replay.py`)
- `dataset.yml`, `replay.json` (dataset metadata and the searches the replay runs)
