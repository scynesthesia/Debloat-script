function Apply-AggressiveTweaks {
    param(
        [Parameter(Mandatory)]
        $HardwareProfile,
        [Parameter(Mandatory)]
        [ref]$FailedPackages,
        $OemServices
    )

    Write-Section "Tweaks adicionales para PC lenta (más agresivo)"

    if ($HardwareProfile.IsLaptop) {
        Write-Host "  [ ] Laptop detectada: se mantiene la hibernación para no romper suspensión." -ForegroundColor Yellow
    } elseif (Ask-YesNo "¿Desactivar hibernación para liberar espacio y arranque rápido?" 's') {
        Write-Host "  [+] Desactivando hibernación"
        try {
            powercfg -h off
        } catch {
            Write-Host "    [-] Error desactivando hibernación: $_" -ForegroundColor Yellow
        }
    } else {
        Write-Host "  [ ] Hibernación sin cambios."
    }

    Write-Host "  [+] Bloqueando apps en segundo plano"
    Set-RegistryValueSafe "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" "LetAppsRunInBackground" 2

    Write-Host "  [+] Debloat extra (PC lenta)"
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
            Write-Host "    [+] Quitando $a"
            try {
                Get-AppxPackage -AllUsers -Name $a | Remove-AppxPackage -ErrorAction SilentlyContinue
            } catch {
                $FailedPackages.Value += $a
                Write-Host "      [-] Error quitando $a : $_" -ForegroundColor Yellow
            }
        }
    }

    if ($OemServices -and $OemServices.Count -gt 0) {
        Write-Host "  [!] Servicios OEM detectados: $($OemServices.DisplayName -join ', ')" -ForegroundColor Yellow
        Write-Host "      Evitando desactivar servicios críticos de fabricante."
    }

    if (-not $OemServices -or $OemServices.Count -eq 0) {
        if (Ask-YesNo "¿Desactivar Print Spooler si no usás impresoras?" 'n') {
            try {
                Stop-Service -Name "Spooler" -ErrorAction SilentlyContinue
                Set-Service -Name "Spooler" -StartupType Disabled
                Write-Host "  [+] Print Spooler desactivado"
            } catch {
                Write-Host "    [-] No se pudo desactivar Spooler: $_" -ForegroundColor Yellow
            }
        }
    } else {
        Write-Host "  [ ] Spooler no se toca por servicios OEM presentes."
    }

    if (Ask-YesNo "¿Bloquear inicio automático de OneDrive?" 's') {
        try {
            taskkill /F /IM OneDrive.exe -ErrorAction SilentlyContinue
            Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "OneDrive" -ErrorAction SilentlyContinue
            Disable-ScheduledTask -TaskPath "\\Microsoft\\OneDrive\\" -TaskName "OneDrive Standalone Update Task-S-1-5-21" -ErrorAction SilentlyContinue | Out-Null
            Write-Host "  [+] OneDrive no se iniciará automáticamente"
        } catch {
            Write-Host "    [-] No se pudo bloquear el auto-start de OneDrive: $_" -ForegroundColor Yellow
        }
    }

    if (Ask-YesNo "¿Desactivar tareas de Consumer Experience (contenido sugerido)?" 's') {
        $tasks = @(
            "\\Microsoft\\Windows\\Customer Experience Improvement Program\\Consolidator",
            "\\Microsoft\\Windows\\Customer Experience Improvement Program\\KernelCeipTask",
            "\\Microsoft\\Windows\\Customer Experience Improvement Program\\UsbCeip",
            "\\Microsoft\\Windows\\Application Experience\\Microsoft Compatibility Appraiser"
        )
        foreach ($t in $tasks) {
            try {
                schtasks /Change /TN $t /Disable | Out-Null
                Write-Host "  [+] Tarea $t desactivada"
            } catch {
                Write-Host "    [-] No se pudo desactivar $t : $_" -ForegroundColor Yellow
            }
        }
    }

    if (Ask-YesNo "¿Usás Copilot? Si no, ¿querés desinstalarlo?" 'n') {
        $copilotPkgs = @()
        $copilotPkgs += Get-AppxPackage -AllUsers -Name "Microsoft.Copilot" -ErrorAction SilentlyContinue
        $copilotPkgs += Get-AppxPackage -AllUsers -Name "*Copilot*" -ErrorAction SilentlyContinue | Where-Object { $_.Name -like '*Copilot*' }

        if ($copilotPkgs.Count -eq 0) {
            Write-Host "  [ ] Copilot no está instalado."
        } else {
            foreach ($pkg in $copilotPkgs | Select-Object -Unique) {
                Write-Host "  [+] Quitando $($pkg.Name)"
                try {
                    $pkg | Remove-AppxPackage -ErrorAction SilentlyContinue
                } catch {
                    $FailedPackages.Value += $pkg.Name
                    Write-Host "    [-] Error quitando $($pkg.Name): $_" -ForegroundColor Yellow
                }
            }
        }
    } else {
        Write-Host "  [ ] Copilot se mantiene instalado."
    }

    if (Ask-YesNo "¿Desactivar inicio automático de Microsoft Teams (personal)?" 's') {
        try {
            taskkill /F /IM Teams.exe -ErrorAction SilentlyContinue
        } catch { }

        try {
            Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "com.squirrel.Teams.Teams" -ErrorAction SilentlyContinue
            Write-Host "  [+] Inicio automático de Teams (personal) desactivado"
        } catch {
            Write-Host "    [-] No se pudo desactivar el auto-start de Teams: $_" -ForegroundColor Yellow
        }
    }

    Clear-DeepTempAndThumbs

    Write-Host ""
    if (Ask-YesNo "¿Quitar OneDrive de este sistema?" 'n') {
        Write-Host "  [+] Intentando desinstalar OneDrive"
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
            Write-Host "    [-] Error quitando OneDrive: $_" -ForegroundColor Yellow
        }
    } else {
        Write-Host "  [ ] OneDrive se mantiene instalado."
    }
}

Export-ModuleMember -Function Apply-AggressiveTweaks
