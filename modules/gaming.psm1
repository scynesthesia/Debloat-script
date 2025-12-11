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

function Get-OrCreate-GamingPlan {
    $planName = "Scynesthesia Gaming Mode"

    try {
        $plans = Get-CimInstance -Namespace root\cimv2\power -ClassName Win32_PowerPlan -ErrorAction Stop
    } catch {
        throw "Unable to query power plans via CIM: $_"
    }

    $existingPlan = $plans | Where-Object { $_.ElementName -eq $planName }
    if ($existingPlan) {
        return $existingPlan
    }

    $activePlan = $plans | Where-Object { $_.IsActive -eq $true } | Select-Object -First 1
    if (-not $activePlan) {
        throw "Unable to detect active power plan."
    }

    $activeGuid = ($activePlan.InstanceID -split '[{}]')[1]
    if (-not $activeGuid) {
        throw "Unable to parse active power plan GUID."
    }

    $duplicateOutput = powercfg -duplicatescheme $activeGuid
    $duplicateMatch  = [regex]::Match($duplicateOutput, '([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})')

    if (-not $duplicateMatch.Success) {
        throw "Unable to duplicate active power scheme."
    }

    $newGuid = $duplicateMatch.Groups[1].Value
    powercfg -changename $newGuid $planName

    $gamingPlan = Get-CimInstance -Namespace root\cimv2\power -ClassName Win32_PowerPlan -ErrorAction Stop |
        Where-Object { $_.ElementName -eq $planName }

    if (-not $gamingPlan) {
        throw "Failed to locate gaming power plan after creation."
    }

    return $gamingPlan
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
                $gamingPlan = Get-OrCreate-GamingPlan
                $gamingGuid = ($gamingPlan.InstanceID -split '[{}]')[1]

                if (-not $gamingGuid) {
                    throw "Unable to parse gaming power plan GUID."
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
                Handle-Error -Context "Applying gaming power settings" -ErrorRecord $_
            }
        } else {
            Write-Host "  [ ] Hardcore power tweaks skipped." -ForegroundColor DarkGray
        }
    }

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

function Get-OrCreate-GamingPlan {
    $planName = "Scynesthesia Gaming Mode"

    try {
        $plans = Get-CimInstance -Namespace root\cimv2\power -ClassName Win32_PowerPlan -ErrorAction Stop
    } catch {
        throw "Unable to query power plans via CIM: $_"
    }

    $existingPlan = $plans | Where-Object { $_.ElementName -eq $planName }
    if ($existingPlan) {
        return $existingPlan
    }

    $activePlan = $plans | Where-Object { $_.IsActive -eq $true } | Select-Object -First 1
    if (-not $activePlan) {
        throw "Unable to detect active power plan."
    }

    $activeGuid = ($activePlan.InstanceID -split '[{}]')[1]
    if (-not $activeGuid) {
        throw "Unable to parse active power plan GUID."
    }

    $duplicateOutput = powercfg -duplicatescheme $activeGuid
    $duplicateMatch  = [regex]::Match($duplicateOutput, '([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})')

    if (-not $duplicateMatch.Success) {
        throw "Unable to duplicate active power scheme."
    }

    $newGuid = $duplicateMatch.Groups[1].Value
    powercfg -changename $newGuid $planName

    $gamingPlan = Get-CimInstance -Namespace root\cimv2\power -ClassName Win32_PowerPlan -ErrorAction Stop |
        Where-Object { $_.ElementName -eq $planName }

    if (-not $gamingPlan) {
        throw "Failed to locate gaming power plan after creation."
    }

    return $gamingPlan
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
                $gamingPlan = Get-OrCreate-GamingPlan
                $gamingGuid = ($gamingPlan.InstanceID -split '[{}]')[1]

                if (-not $gamingGuid) {
                    throw "Unable to parse gaming power plan GUID."
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
                Handle-Error -Context "Applying gaming power settings" -ErrorRecord $_
            }
        } else {
            Write-Host "  [ ] Hardcore power tweaks skipped." -ForegroundColor DarkGray
        }
    }
    function Optimize-ProcessorScheduling {
    Write-Section "Processor Scheduling (Win32Priority)"
    Write-Host "Tweaks CPU allocation for active windows. Recommended for competitive gaming." -ForegroundColor Gray
    
    # 28 Hex = 40 Decimal (Short Intervals, Fixed, High Boost). 
    # Best for consistent frametimes (less jitter than 26 Hex).
    if (Ask-YesNo "Apply Fixed Priority Separation (28 Hex) for lower input latency?" 'n') {
        Set-RegistryValueSafe "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" "Win32PrioritySeparation" 40
        Write-Host "  [+] Processor scheduling set to 28 Hex (Fixed/Short)." -ForegroundColor Green
    } else {
        Write-Host "  [ ] Processor scheduling left unchanged." -ForegroundColor DarkGray
    }
}

function Enable-MsiModeSafe {
    Write-Section "MSI Mode (Message Signaled Interrupts)"
    Write-Host "Reduces DPC latency by changing how GPU/Network communicate with CPU." -ForegroundColor Gray
    Write-Host "WARNING: Only compatible devices will be touched. Reboot required." -ForegroundColor Yellow

    if (Ask-YesNo "Attempt to force MSI Mode on GPU and Network adapters?" 'n') {
        # Target Class GUIDs: Display and Network adapters
        $targetClasses = @(
            "{4d36e968-e325-11ce-bfc1-08002be10318}", # Display
            "{4d36e972-e325-11ce-bfc1-08002be10318}"  # Network
        )

        $count = 0
        foreach ($classGuid in $targetClasses) {
            # Get only present devices
            $devices = Get-PnpDevice -ClassGuid $classGuid -Status OK -ErrorAction SilentlyContinue
            foreach ($dev in $devices) {
                try {
                    # Path to the device parameters in registry
                    $regPath = "HKLM\SYSTEM\CurrentControlSet\Enum\$($dev.InstanceId)\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties"
                    
                    # SAFETY CHECK: We only touch it if the key ALREADY exists (Driver supports it)
                    if (Test-Path $regPath) {
                        $currentVal = Get-ItemProperty -Path $regPath -Name "MSISupported" -ErrorAction SilentlyContinue
                        
                        if ($currentVal.MSISupported -ne 1) {
                            Set-RegistryValueSafe $regPath "MSISupported" 1
                            Write-Host "  [+] MSI enabled for: $($dev.FriendlyName)" -ForegroundColor Green
                            $count++
                        } else {
                            Write-Host "  [=] MSI already active for: $($dev.FriendlyName)" -ForegroundColor DarkGray
                        }
                    }
                } catch {}
            }
        }
        
        if ($count -gt 0) {
            Write-Host ""
            Write-Host "  [!] A REBOOT is required to apply MSI Mode changes." -ForegroundColor Magenta
        } else {
            Write-Host "  [i] No applicable devices found or already enabled." -ForegroundColor DarkGray
        }
    } else {
        Write-Host "  [ ] MSI Mode skipped." -ForegroundColor DarkGray
    }
}

Export-ModuleMember -Function Optimize-NetworkLatency, Optimize-GamingScheduler, Apply-CustomGamingPowerSettings, Optimize-ProcessorScheduling, Enable-MsiModeSafe
