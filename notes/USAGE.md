# Usage

This repository’s main entrypoint is:

- `scripts/detect-and-remove-dcomlaunch-u-services.ps1`

The script is **detection-only by default**. It will not modify the system unless you explicitly pass `-Remediate`.

## Prerequisites

- Run **PowerShell as Administrator**.
- If services/processes keep respawning, consider running from **Safe Mode**.
- Start with `-WhatIf` before applying any remediation.

## Recommended execution order

1) Detect (no changes)

```powershell
.\scripts\detect-and-remove-dcomlaunch-u-services.ps1
```

2) Detect + validate candidates exist as services

```powershell
.\scripts\detect-and-remove-dcomlaunch-u-services.ps1 -ValidateServices
```

3) Dry-run remediation (prints intended changes)

```powershell
.\scripts\detect-and-remove-dcomlaunch-u-services.ps1 -Remediate -WhatIf
```

4) Apply remediation

```powershell
.\scripts\detect-and-remove-dcomlaunch-u-services.ps1 -Remediate
```

## Targeting a specific service

If you already know the service name (for example from prior triage), you can skip auto-detection and operate on a single target:

```powershell
.\scripts\detect-and-remove-dcomlaunch-u-services.ps1 -ServiceName u952451
```

Dry-run remediation for a specific service:

```powershell
.\scripts\detect-and-remove-dcomlaunch-u-services.ps1 -ServiceName u952451 -Remediate -WhatIf
```

Apply remediation for a specific service:

```powershell
.\scripts\detect-and-remove-dcomlaunch-u-services.ps1 -ServiceName u952451 -Remediate
```

## Optional switches (opt-in, riskier)

### Kill case-study processes

This mirrors the original case study cleanup behavior. It is **opt-in** and uses process-name matching:
- `svctrl64.exe`
- `u*.exe` (wildcard; low-confidence, use caution)

Dry-run:

```powershell
.\scripts\detect-and-remove-dcomlaunch-u-services.ps1 -Remediate -KillProcesses -WhatIf
```

Apply:

```powershell
.\scripts\detect-and-remove-dcomlaunch-u-services.ps1 -Remediate -KillProcesses
```

### Delete case-study artifacts

This is the riskiest option because it deletes files/directories under `C:\Windows\System32`.

Default targets (case-study oriented):
- `C:\Windows\System32\<ServiceName>.dll`
- `C:\Windows\System32\svctrl64.exe`
- `C:\Windows\System32\svcinsty64.exe`
- `C:\Windows\System32\wsvcz\`

Dry-run:

```powershell
.\scripts\detect-and-remove-dcomlaunch-u-services.ps1 -Remediate -DeleteArtifacts -WhatIf
```

Apply:

```powershell
.\scripts\detect-and-remove-dcomlaunch-u-services.ps1 -Remediate -DeleteArtifacts
```

Add extra paths (optional):

```powershell
.\scripts\detect-and-remove-dcomlaunch-u-services.ps1 -Remediate -DeleteArtifacts -ExtraPaths "C:\Windows\System32\wsvcz\wlogz.dat" -WhatIf
```

## Backups and outputs

- Before modifying `DcomLaunch`, the script exports the Svchost registry key to a `.reg` file in `%TEMP%` by default (or the directory specified by `-BackupDir`).

## Exit behavior

- If no entries match the heuristic, the script exits successfully.
- If matches are found and `-Remediate` is **not** set, the script reports matches and exits with a non-zero code to make “detection found something” visible in automation.

## What the script changes in remediation mode

When `-Remediate` is provided, the script may:

- Stop / disable / delete the target service(s) (if present)
- Remove target service name(s) from `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost` → `DcomLaunch`
- Optionally kill processes (`-KillProcesses`)
- Optionally delete case-study artifacts (`-DeleteArtifacts`)

## Reference

- Case-study IOCs: `notes/indicators-of-compromise.md`
- Original manual command log (chronological): `notes/raw-commands.txt`
