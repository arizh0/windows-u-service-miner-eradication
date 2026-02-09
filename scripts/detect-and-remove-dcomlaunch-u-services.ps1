<#
detect-and-remove-dcomlaunch-u-services.ps1

Detects suspicious u###### entries in Svchost "DcomLaunch" group and optionally remediates:
- stop/disable/delete the service
- remove it from DcomLaunch
- optionally kill case-study processes
- optionally delete case-study artifacts

Default behavior: DETECT ONLY.

Examples:
  # Detect only
  .\detect-and-remove-dcomlaunch-u-services.ps1

  # Detect only, show service existence check
  .\detect-and-remove-dcomlaunch-u-services.ps1 -ValidateServices

  # Remediate (dry run)
  .\detect-and-remove-dcomlaunch-u-services.ps1 -Remediate -WhatIf

  # Remediate for specific service only
  .\detect-and-remove-dcomlaunch-u-services.ps1 -Remediate -ServiceName u952451

  # Remediate + kill processes + delete artifacts (risky)
  .\detect-and-remove-dcomlaunch-u-services.ps1 -Remediate -KillProcesses -DeleteArtifacts
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    # If provided, operate only on this service name (skips auto-detection list).
    [string]$ServiceName,

    # If set, performs remediation actions. If not set, script only reports.
    [switch]$Remediate,

    # If set, checks whether the detected service names actually exist via sc.exe query.
    [switch]$ValidateServices,

    # Opt-in: kill case-study processes (svctrl64.exe and u*.exe)
    [switch]$KillProcesses,

    # Opt-in: delete case-study artifacts (System32 paths). Risky.
    [switch]$DeleteArtifacts,

    # Optional additional paths to delete (files or directories).
    [string[]]$ExtraPaths = @(),

    # Backup directory for registry export.
    [string]$BackupDir = $env:TEMP,

    # Heuristic for suspicious service naming.
    [string]$NameRegex = '^u\d{6,}$'
)

$ErrorActionPreference = "Stop"

function Assert-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Run PowerShell as Administrator."
    }
}

function Sc-Query {
    param([string]$Name)

    $out = & sc.exe query $Name 2>&1
    $code = $LASTEXITCODE
    [PSCustomObject]@{
        Output   = $out
        ExitCode = $code
        Exists   = ($code -eq 0)
    }
}

function Backup-SvchostKey {
    param([string]$OutFile)

    $key = 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost'
    if ($PSCmdlet.ShouldProcess($key, "Export registry key to $OutFile")) {
        & reg.exe export "$key" "$OutFile" /y | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "reg export failed (exit code $LASTEXITCODE)" }
    }
}

function Get-DcomLaunchEntries {
    $k = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost'
    $v = 'DcomLaunch'
    return (Get-ItemProperty -Path $k -Name $v -ErrorAction Stop).$v
}

function Set-DcomLaunchEntries {
    param([string[]]$Entries)

    $k = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost'
    $v = 'DcomLaunch'
    if ($PSCmdlet.ShouldProcess("$k\$v", "Set DcomLaunch entries (REG_MULTI_SZ)")) {
        Set-ItemProperty -Path $k -Name $v -Value $Entries -ErrorAction Stop
    }
}

function Remove-From-DcomLaunch {
    param([string]$Svc)

    $current = @(Get-DcomLaunchEntries)
    if (-not $current -or $current.Count -eq 0) {
        Write-Host "DcomLaunch list is empty."
        return
    }

    if ($current -notcontains $Svc) {
        Write-Host "Service '$Svc' not present in DcomLaunch. No registry change."
        return
    }

    $new = $current | Where-Object { $_ -ne $Svc }

    Write-Host "DcomLaunch BEFORE:"
    $current | ForEach-Object { Write-Host "  - $_" }

    Write-Host "DcomLaunch AFTER (removing '$Svc'):"
    $new | ForEach-Object { Write-Host "  - $_" }

    Set-DcomLaunchEntries -Entries $new
}

function Stop-Disable-Delete-Service {
    param([string]$Svc)

    $q = Sc-Query -Name $Svc
    if (-not $q.Exists) {
        Write-Host "Service '$Svc' not found (sc exit code $($q.ExitCode)). Skipping stop/disable/delete."
        return
    }

    if ($PSCmdlet.ShouldProcess("service $Svc", "Stop")) {
        & sc.exe stop $Svc | Out-Null
    }
    if ($PSCmdlet.ShouldProcess("service $Svc", "Disable start")) {
        & sc.exe config $Svc start= disabled | Out-Null
    }
    if ($PSCmdlet.ShouldProcess("service $Svc", "Delete")) {
        & sc.exe delete $Svc | Out-Null
    }
}

function Clear-Attributes {
    param([string]$Path)
    try { & attrib.exe -s -h -r $Path /s /d 2>$null | Out-Null } catch {}
}

function TakeOwn-And-GrantAdmins {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) { return }

    if (Test-Path -LiteralPath $Path -PathType Container) {
        & takeown.exe /f $Path /r /d y | Out-Null
        & icacls.exe $Path /grant Administrators:F /t | Out-Null
        if ($LASTEXITCODE -ne 0) {
            & icacls.exe $Path /grant "*S-1-5-32-544:F" /t | Out-Null
        }
    } else {
        & takeown.exe /f $Path | Out-Null
        & icacls.exe $Path /grant Administrators:F | Out-Null
        if ($LASTEXITCODE -ne 0) {
            & icacls.exe $Path /grant "*S-1-5-32-544:F" | Out-Null
        }
    }
}

function Remove-PathForce {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        Write-Host "Not found (skip): $Path"
        return
    }

    Write-Host "Target: $Path"
    Clear-Attributes -Path $Path
    TakeOwn-And-GrantAdmins -Path $Path
    Clear-Attributes -Path $Path

    if ($PSCmdlet.ShouldProcess($Path, "Delete")) {
        if (Test-Path -LiteralPath $Path -PathType Container) {
            Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction SilentlyContinue
        } else {
            Remove-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
        }
    }
}

function Kill-CaseStudyProcesses {
    if ($PSCmdlet.ShouldProcess("process svctrl64.exe", "taskkill /f")) {
        & taskkill.exe /f /im svctrl64.exe 2>$null | Out-Null
    }
    if ($PSCmdlet.ShouldProcess("process u*.exe", "taskkill /f")) {
        & taskkill.exe /f /im u*.exe 2>$null | Out-Null
    }
}

function Get-Targets {
    param([string]$Regex)

    $entries = @(Get-DcomLaunchEntries)

    if ($ServiceName -and $ServiceName.Trim() -ne "") {
        return @($ServiceName.Trim())
    }

    $sus = $entries | Where-Object { $_ -match $Regex }
    return @($sus)
}

try {
    Assert-Admin

    $entries = @(Get-DcomLaunchEntries)
    Write-Host "Svchost group 'DcomLaunch' entries:"
    $entries | ForEach-Object { Write-Host "  - $_" }

    Write-Host ""
    Write-Host "Heuristic match regex: $NameRegex"

    $targets = @(Get-Targets -Regex $NameRegex)

    if (-not $targets -or $targets.Count -eq 0) {
        Write-Host "No entries matched the heuristic."
        exit 0
    }

    Write-Host ""
    Write-Host "Matched candidate service names:"
    $targets | ForEach-Object { Write-Host "  * $_" }

    if ($ValidateServices) {
        Write-Host ""
        Write-Host "Service existence checks:"
        foreach ($t in $targets) {
            $q = Sc-Query -Name $t
            $status = if ($q.Exists) { "EXISTS" } else { "MISSING" }
            Write-Host ("  {0}: {1} (sc exit {2})" -f $t, $status, $q.ExitCode)
        }
    }

    if (-not $Remediate) {
        Write-Host ""
        Write-Host "Detection only. To remediate, re-run with -Remediate (use -WhatIf first)."
        exit 2
    }

    Write-Host ""
    Write-Host "Remediation enabled."

    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $backupFile = Join-Path -Path $BackupDir -ChildPath "SvchostKey-backup-$timestamp.reg"

    Write-Host "Backing up Svchost registry key to: $backupFile"
    Backup-SvchostKey -OutFile $backupFile

    foreach ($t in $targets) {
        Write-Host ""
        Write-Host "=== Remediating: $t ==="

        Write-Host "[1/4] Stop/disable/delete service: $t"
        Stop-Disable-Delete-Service -Svc $t

        Write-Host "[2/4] Remove from DcomLaunch: $t"
        Remove-From-DcomLaunch -Svc $t

        if ($KillProcesses) {
            Write-Host "[3/4] Kill case-study processes (opt-in)"
            Kill-CaseStudyProcesses
        } else {
            Write-Host "[3/4] Process killing skipped"
        }

        if ($DeleteArtifacts) {
            Write-Host "[4/4] Delete artifacts (opt-in)"

            $defaultArtifacts = @(
                ("C:\Windows\System32\{0}.dll" -f $t),
                "C:\Windows\System32\svctrl64.exe",
                "C:\Windows\System32\svcinsty64.exe",
                "C:\Windows\System32\wsvcz"
            )

            $artifactTargets = @($defaultArtifacts + $ExtraPaths) |
                Where-Object { $_ -and $_.Trim() -ne "" } |
                Select-Object -Unique

            Write-Host "Artifact targets:"
            $artifactTargets | ForEach-Object { Write-Host "  - $_" }

            foreach ($p in $artifactTargets) {
                Remove-PathForce -Path $p
            }
        } else {
            Write-Host "[4/4] Artifact deletion skipped"
        }
    }

    Write-Host ""
    Write-Host "Manual validation recommended:"
    Write-Host "  reg query `"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost`" /v DcomLaunch"
    Write-Host "  sc query <service>"
    Write-Host "  reg query `"HKLM\SYSTEM\CurrentControlSet\Services\<service>`" /s"
    Write-Host "Done."
}
catch {
    Write-Error $_
    exit 1
}
