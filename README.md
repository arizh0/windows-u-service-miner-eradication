# Windows Svchost DcomLaunch Miner Removal (u###### service persistence)

This repository documents a real-world detection and removal workflow for a Windows malware infection that behaved like a crypto-miner and persisted as a randomly named service (pattern: `u######`) registered under the Svchost `DcomLaunch` group. In the observed case, the infection also dropped artifacts into `C:\Windows\System32` (examples: `svctrl64.exe`, `wsvcz\wlogz.dat`, and a service-linked DLL).

This is a case study plus a practical checklist. It is not guaranteed to remove all variants or persistence mechanisms.

## Scope and threat model

What this targets (based on the observed case):
- Persistence via a suspicious service name like `u######` (example observed: `u952451`)
- The service name being added to the Svchost group value `DcomLaunch` (under `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost`)
- Related binaries and data in `C:\Windows\System32\` (case-specific examples below)

What this does not guarantee:
- Full coverage of additional persistence (Scheduled Tasks, WMI subscriptions, Run keys, services with other names, drivers/rootkits)
- Clean-up of lateral movement, credential theft, or secondary payloads
- That a machine is trustworthy again after removal (a reimage may still be the correct decision)

## Safety / operational notes (read before running)

- Run as **Administrator**.
- Prefer **Safe Mode** if processes/services keep respawning.
- Editing the Svchost group list and deleting from `System32` is inherently risky. Export registry keys first and double-check all paths.
- If this is a company device or you need assurance, treat it as an incident: preserve evidence first and consider reimaging after triage.

## Observed indicators (IOCs) in this case

Registry:
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost` → value `DcomLaunch` contains a suspicious entry like `u######` (example: `u952451`)
  - Note: `DcomLaunch` is typically a multi-string (REG_MULTI_SZ) list of service names hosted under that Svchost group.

Services:
- Suspicious service named like `u######` (example: `u952451`)
- Service registry key: `HKLM\SYSTEM\CurrentControlSet\Services\u######`

Artifacts (examples observed; may differ on your system):
- `C:\Windows\System32\svctrl64.exe`
- `C:\Windows\System32\svcinsty64.exe`
- `C:\Windows\System32\wsvcz\wlogz.dat`
- `C:\Windows\System32\u######.dll` (example: `C:\Windows\System32\u952451.dll`)
