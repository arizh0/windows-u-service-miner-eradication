# Indicators of Compromise (IOCs)

This document lists indicators observed in a single real-world malware infection. They are case-specific and should be treated as heuristic signals, not definitive signatures.

## Service and persistence indicators

- Random-looking Windows service name following the pattern `u######`  
  Example observed: `u952451`

- Svchost group modification (`DcomLaunch`)  
  Registry path: `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost`  
  Value: `DcomLaunch`  
  Indicator: presence of a suspicious `u######` entry inside the `DcomLaunch` list (often `REG_MULTI_SZ`)

- Service registry key  
  `HKLM\SYSTEM\CurrentControlSet\Services\u######`

## File system indicators

The following artifacts were observed on disk. File names and paths may vary.

- Executables  
  - `C:\Windows\System32\svctrl64.exe`  
  - `C:\Windows\System32\svcinsty64.exe`

- Service-linked DLL  
  - `C:\Windows\System32\u######.dll`  
    Example observed: `C:\Windows\System32\u952451.dll`

- Data / working directory  
  - `C:\Windows\System32\wsvcz\`  
  - `C:\Windows\System32\wsvcz\wlogz.dat`

## Process indicators

- Running process matching dropped executable  
  - `svctrl64.exe`

- Case-specific observation / cleanup target  
  - `u*.exe` (wildcard used during cleanup; treat as low-confidence indicator)

## Behavioral indicators

- Elevated or sustained CPU usage consistent with mining activity
- Not detected by the AV products tested in this case (may vary over time)
- Files protected by modified ACLs and/or hidden/system attributes
- Required ownership and permission changes before deletion

## Notes

- The `u######` service name pattern is a heuristic, not a guarantee of maliciousness.
- Svchost group modification is a common persistence technique; verify with multiple signals.
- Presence of one indicator alone may be insufficient; multiple indicators together increase confidence.
- For high-assurance environments, reimaging the system may still be required.
