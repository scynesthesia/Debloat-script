function Optimize-NetworkLatency {
    Write-Section "Latency Optimization (Ping/Jitter)"
    Write-Host "Recommended for competitive online games (Valorant, CS2, CoD)." -ForegroundColor Gray

    if (Ask-YesNo "Disable Network Throttling and optimize network responsiveness?" 'y') {
        # Network Throttling + SystemResponsiveness
        Set-RegistryValueSafe "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" "NetworkThrottlingIndex" 0xffffffff
        Set-RegistryValueSafe "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" "SystemResponsiveness" 0

        $profile = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile"
        if ($profile.SystemResponsiveness -ne 0) {
            Write-Warning "SystemResponsiveness could not be set to 0. This may be blocked by TrustedInstaller or insufficient permissions."
        }
        if ($profile.NetworkThrottlingIndex -ne 0xffffffff) {
            Write-Warning "NetworkThrottlingIndex could not be set. Check permissions."
        }

        # Nagle / TCP at the interface level
        $tcpParams  = "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"
        $interfaces = Get-ChildItem $tcpParams -ErrorAction SilentlyContinue
        foreach ($iface in $interfaces) {
            Set-RegistryValueSafe $iface.PSPath "TcpAckFrequency" 1
            Set-RegistryValueSafe $iface.PSPath "TCPNoDelay" 1
        }

        Write-Host "  [+] Network optimized for ultra-low latency." -ForegroundColor Green
    } else {
        Write-Host "  [ ] Network tweaks skipped." -ForegroundColor DarkGray
    }
}

function Optimize-GamingScheduler {
    Write-Section "Process Priority (Gaming)"

    if (Ask-YesNo "Prioritize GPU/CPU for foreground games?" 'y') {
        $gamesPath = "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"

        Set-RegistryValueSafe $gamesPath "GPU Priority" 8
        Set-RegistryValueSafe $gamesPath "Priority" 6
        Set-RegistryValueSafe $gamesPath "Scheduling Category" "High" ([Microsoft.Win32.RegistryValueKind]::String)
        Set-RegistryValueSafe $gamesPath "SFIO Priority" "High" ([Microsoft.Win32.RegistryValueKind]::String)

        # SystemResponsiveness already set to 0 in Optimize-NetworkLatency
        Write-Host "  [+] Scheduler optimized for games." -ForegroundColor Green
    } else {
        Write-Host "  [ ] Scheduler left unchanged." -ForegroundColor DarkGray
    }
}

function Apply-CustomGamingPowerSettings {
    Write-Section "Power Plan: 'Custom Gaming Tweaks'"

    $isLaptop = Get-CimInstance -ClassName Win32_Battery -ErrorAction SilentlyContinue
    if ($isLaptop) {
        Write-Host "  [!] Laptop detected: these settings increase power draw and temperatures." -ForegroundColor Yellow
        Write-Host "      Recommended only while plugged into AC power." -ForegroundColor Yellow
    }

    Write-Host "Applying adjustments to the 'Scynesthesia Gaming Mode' plan." -ForegroundColor DarkGray

    if (Ask-YesNo "Apply hardcore power tweaks to prioritize FPS?" 'n') {
        try {
            $activeSchemeOutput = powercfg /getactivescheme
            $activeSchemeMatch  = [regex]::Match($activeSchemeOutput, '([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})')
            if (-not $activeSchemeMatch.Success) {
                throw "Unable to detect active power scheme GUID."
            }

            $activeGuid = $activeSchemeMatch.Groups[1].Value

            $schemeListOutput = powercfg /list
            $gamingGuid = $null
            $schemeMatches = [regex]::Matches($schemeListOutput, 'Power Scheme GUID:\s*([0-9a-fA-F-]+)\s*\(([^)]+)\)')

            foreach ($match in $schemeMatches) {
                if ($match.Groups[2].Value -eq "Scynesthesia Gaming Mode") {
                    $gamingGuid = $match.Groups[1].Value
                    break
                }
            }

            if (-not $gamingGuid) {
                $duplicateOutput = powercfg -duplicatescheme $activeGuid
                $duplicateMatch  = [regex]::Match($duplicateOutput, '([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})')

                if (-not $duplicateMatch.Success) {
                    throw "Unable to duplicate active power scheme."
                }

                $gamingGuid = $duplicateMatch.Groups[1].Value
                powercfg -changename $gamingGuid "Scynesthesia Gaming Mode"
            }

            # 1) Disks / NVMe
            powercfg /setacvalueindex $gamingGuid SUB_DISK DISKIDLE 0
            powercfg /setacvalueindex $gamingGuid SUB_DISK 0b2d69d7-a2a1-449c-9680-f91c70521c60 0

            # 2) CPU / Core parking / EPP
            powercfg /setacvalueindex $gamingGuid SUB_PROCESSOR PROCTHROTTLEMIN 100
            powercfg /setacvalueindex $gamingGuid SUB_PROCESSOR 0cc5b647-c1df-4637-891a-dec35c318583 100
            powercfg /setacvalueindex $gamingGuid SUB_PROCESSOR 36687f9e-e3a5-4dbf-b1dc-15eb381c6863 0

            # 3) USB selective suspend OFF
            powercfg /setacvalueindex $gamingGuid `
                2a737441-1930-4402-8d77-b2bebba308a3 `
                48e6b7a6-50f5-4782-a5d4-53bb8f07e226 0

            # 4) PCIe Link State OFF
            powercfg /setacvalueindex $gamingGuid `
                501a4d13-42af-4429-9fd1-a8218c268e20 `
                ee12f906-d277-404b-b6da-e5fa1a576df5 0

            powercfg /setactive $gamingGuid

            Write-Host "  [+] Power settings for gaming applied." -ForegroundColor Green
        } catch {
            Write-Host "  [-] Error applying power settings: $_" -ForegroundColor Yellow
        }
    } else {
        Write-Host "  [ ] Hardcore power tweaks skipped." -ForegroundColor DarkGray
    }
}

Export-ModuleMember -Function Optimize-NetworkLatency, Optimize-GamingScheduler, Apply-CustomGamingPowerSettings
