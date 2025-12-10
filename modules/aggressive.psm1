function Apply-AggressiveTweaks {
    param(
        [Parameter(Mandatory)]
        $HardwareProfile,
        [Parameter(Mandatory)]
        [ref]$FailedPackages,
        $OemServices
    )

    Write-Section "Additional tweaks for slow PCs (more aggressive)"

    if ($HardwareProfile.IsLaptop) {
        Write-Host "  [ ] Laptop detected: hibernation kept to avoid breaking sleep." -ForegroundColor Yellow
    } elseif (Ask-YesNo "Disable hibernation to free disk space and speed up boot?" 'y') {
        Write-Host "  [+] Disabling hibernation"
        try {
            powercfg -h off
        } catch {
            Write-Host "    [-] Error disabling hibernation: $_" -ForegroundColor Yellow
        }
    } else {
        Write-Host "  [ ] Hibernation left unchanged."
    }

    Write-Host "  [+] Blocking background apps"
    Set-RegistryValueSafe "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" "LetAppsRunInBackground" 2

    Write-Host "  [+] Additional debloat for slow PCs"
    $extra = @(
        "Microsoft.People",
        "Microsoft.SkypeApp",
        "Microsoft.ZuneMusic",
        "Microsoft.ZuneVideo",
        "Microsoft.MicrosoftOfficeHub",
        "Microsoft.OneConnect"
    )
    foreach ($a in $extra) {
        $pkg = Get-AppxPackage -AllUsers -Name $a -ErrorAction SilentlyContinue
        if ($pkg) {
            Write-Host "    [+] Removing $a"
            try {
                Get-AppxPackage -AllUsers -Name $a | Remove-AppxPackage -ErrorAction SilentlyContinue
            } catch {
                $FailedPackages.Value += $a
                Write-Host "      [-] Error removing $a : $_" -ForegroundColor Yellow
            }
        }
    }

    if ($OemServices -and $OemServices.Count -gt 0) {
        Write-Host "  [!] OEM services detected: $($OemServices.DisplayName -join ', ')" -ForegroundColor Yellow
        Write-Host "      Skipping OEM services to avoid breaking vendor tools."
    }

    if (-not $OemServices -or $OemServices.Count -eq 0) {
        if (Ask-YesNo "Disable Print Spooler if you do not use printers?" 'n') {
            try {
                Stop-Service -Name "Spooler" -ErrorAction SilentlyContinue
                Set-Service -Name "Spooler" -StartupType Disabled
                Write-Host "  [+] Print Spooler disabled"
            } catch {
                Write-Host "    [-] Could not disable Spooler: $_" -ForegroundColor Yellow
            }
        }
    } else {
        Write-Host "  [ ] Spooler left untouched because OEM services are present."
    }

    if (Ask-YesNo "Block OneDrive from starting automatically?" 'y') {
        try {
            taskkill /F /IM OneDrive.exe -ErrorAction SilentlyContinue
            Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "OneDrive" -ErrorAction SilentlyContinue
            Disable-ScheduledTask -TaskPath "\\Microsoft\\OneDrive\\" -TaskName "OneDrive Standalone Update Task-S-1-5-21" -ErrorAction SilentlyContinue | Out-Null
            Write-Host "  [+] OneDrive will not auto-start"
        } catch {
            Write-Host "    [-] Could not block OneDrive auto-start: $_" -ForegroundColor Yellow
        }
    }

    if (Ask-YesNo "Disable Consumer Experience tasks (suggested content)?" 'y') {
        $tasks = @(
            "\\Microsoft\\Windows\\Customer Experience Improvement Program\\Consolidator",
            "\\Microsoft\\Windows\\Customer Experience Improvement Program\\KernelCeipTask",
            "\\Microsoft\\Windows\\Customer Experience Improvement Program\\UsbCeip",
            "\\Microsoft\\Windows\\Application Experience\\Microsoft Compatibility Appraiser"
        )
        foreach ($t in $tasks) {
            try {
                schtasks /Change /TN $t /Disable | Out-Null
                Write-Host "  [+] Task $t disabled"
            } catch {
                Write-Host "    [-] Could not disable $t : $_" -ForegroundColor Yellow
            }
        }
    }

    if (Ask-YesNo "Do you use Copilot? If not, uninstall it?" 'n') {
        $copilotPkgs = @()
        $copilotPkgs += Get-AppxPackage -AllUsers -Name "Microsoft.Copilot" -ErrorAction SilentlyContinue
        $copilotPkgs += Get-AppxPackage -AllUsers -Name "*Copilot*" -ErrorAction SilentlyContinue | Where-Object { $_.Name -like '*Copilot*' }

        if ($copilotPkgs.Count -eq 0) {
            Write-Host "  [ ] Copilot is not installed."
        } else {
            foreach ($pkg in $copilotPkgs | Select-Object -Unique) {
                Write-Host "  [+] Removing $($pkg.Name)"
                try {
                    $pkg | Remove-AppxPackage -ErrorAction SilentlyContinue
                } catch {
                    $FailedPackages.Value += $pkg.Name
                    Write-Host "    [-] Error removing $($pkg.Name): $_" -ForegroundColor Yellow
                }
            }
        }
    } else {
        Write-Host "  [ ] Copilot stays installed."
    }

    if (Ask-YesNo "Disable auto-start for Microsoft Teams (personal)?" 'y') {
        try {
            taskkill /F /IM Teams.exe -ErrorAction SilentlyContinue
        } catch { }

        try {
            Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "com.squirrel.Teams.Teams" -ErrorAction SilentlyContinue
            Write-Host "  [+] Auto-start for Teams (personal) disabled"
        } catch {
            Write-Host "    [-] Could not disable Teams auto-start: $_" -ForegroundColor Yellow
        }
    }

    Clear-DeepTempAndThumbs

    Write-Host ""
    if (Ask-YesNo "Remove OneDrive from this system?" 'n') {
        Write-Host "  [+] Attempting to uninstall OneDrive"
        try {
            taskkill /F /IM OneDrive.exe -ErrorAction SilentlyContinue
            $pathSys = "$env:SystemRoot\System32\OneDriveSetup.exe"
            $pathWow = "$env:SystemRoot\SysWOW64\OneDriveSetup.exe"
            if (Test-Path $pathWow) {
                & $pathWow /uninstall
            } elseif (Test-Path $pathSys) {
                & $pathSys /uninstall
            }
        } catch {
            Write-Host "    [-] Error removing OneDrive: $_" -ForegroundColor Yellow
        }
    } else {
        Write-Host "  [ ] OneDrive stays installed."
    }
}

Export-ModuleMember -Function Apply-AggressiveTweaks
