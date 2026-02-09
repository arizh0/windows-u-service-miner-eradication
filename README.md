# Windows Svchost DcomLaunch Miner Removal (u###### service persistence)

This repository contains a single PowerShell workflow script that detects (and optionally remediates) a Windows malware persistence pattern observed in the wild:

- A randomly named service matching the pattern `u######` (example observed: `u952451`)
- The service name added to the Svchost group value `DcomLaunch`
- Case-specific artifacts dropped into `C:\Windows\System32` (for example: `svctrl64.exe`, `wsvcz\wlogz.dat`, and a service-linked DLL)

The focus of this repo is the code: a conservative detector-by-default script that can be switched into remediation mode when explicitly requested.

This is a case study plus an automation template. It is not guaranteed to remove all variants or persistence mechanisms.

## Contents

- `scripts/detect-and-remove-dcomlaunch-u-services.ps1` — combined detector + optional remover
- `notes/indicators-of-compromise.md` — observed IOCs from the case study
- `notes/raw-commands.txt` — the original manual command sequence used in the case (for transparency)

## Script overview

The script reads the Svchost `DcomLaunch` membership list and identifies entries that match the default heuristic regex `^u\d{6,}$`. It supports:

- Detection-only reporting by default (no changes)
- Optional validation of candidates using `sc.exe query` exit codes
- Explicit remediation mode (`-Remediate`) that can:
  - stop/disable/delete the service(s)
  - remove service name(s) from `DcomLaunch`
  - optionally kill case-study processes (`-KillProcesses`)
  - optionally delete case-study artifacts (`-DeleteArtifacts`)
- Safe dry-runs via PowerShell `-WhatIf` / `-Confirm`

Design choices:

- No remediation actions occur unless `-Remediate` is provided.
- Destructive actions (process killing, file deletion) are opt-in.
- Registry changes are preceded by a registry export backup.

## Usage

See `notes/USAGE.md` for exact commands and recommended execution order (detect → validate → dry-run → remediate).

## Safety and limitations

- This workflow targets one observed persistence technique (Svchost group modification + service).
- It does not guarantee detection or removal of other persistence mechanisms (Scheduled Tasks, WMI subscriptions, Run keys, drivers/rootkits) or secondary payloads.
- If you need high assurance that the system is trustworthy again, reimaging may still be the correct decision.

