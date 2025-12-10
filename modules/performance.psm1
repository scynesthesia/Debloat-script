function Get-HardwareProfile {
    $battery = Get-CimInstance -ClassName Win32_Battery -ErrorAction SilentlyContinue
    $system = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
    $memoryBytes = $system.TotalPhysicalMemory
    $memoryGB = if ($memoryBytes) { [math]::Round($memoryBytes / 1GB, 1) } else { 0 }

    $disks = Get-PhysicalDisk -ErrorAction SilentlyContinue
    $hasSSD = $false
    $hasHDD = $false
    foreach ($disk in $disks) {
        switch ($disk.MediaType) {
            'SSD' { $hasSSD = $true }
            'HDD' { $hasHDD = $true }
            default {
                if ($disk.RotationRate -gt 0) { $hasHDD = $true }
            }
        }
    }

    [pscustomobject]@{
        IsLaptop       = $battery -ne $null
        TotalMemoryGB  = $memoryGB
        MemoryCategory = if ($memoryGB -lt 6) { 'Low' } else { 'Normal' }
        HasSSD         = $hasSSD
        HasHDD         = $hasHDD -or -not $hasSSD
    }
}

function Get-OEMServiceInfo {
    $patterns = 'Dell','Alienware','HP','Hewlett','Lenovo','Acer','ASUS','MSI','Samsung','Razer'
    $services = Get-Service | Where-Object { $patterns -contains ($_.DisplayName.Split(' ')[0]) -or $patterns -contains ($_.ServiceName.Split(' ')[0]) }
    $services
}

function Handle-SysMainPrompt {
    param(
        [Parameter(Mandatory)]
        $HardwareProfile
    )

    Write-Section "SysMain (Superfetch)"
    $hint = if ($HardwareProfile.HasHDD -and -not $HardwareProfile.HasSSD) { 'HDD detected: SysMain can speed up launches.' } else { 'SSD detected: you can disable it to avoid extra IO.' }
    Write-Host $hint -ForegroundColor Gray

    $defaultChoice = if ($HardwareProfile.HasSSD -and -not $HardwareProfile.HasHDD) { 'y' } else { 'n' }
    if (Ask-YesNo "Disable SysMain to prioritize resources?" $defaultChoice) {
        try {
            Stop-Service -Name "SysMain" -ErrorAction SilentlyContinue
            Set-Service -Name "SysMain" -StartupType Disabled
            Write-Host "  [+] SysMain disabled"
        } catch {
            Handle-Error -Context "Disabling SysMain service" -ErrorRecord $_
        }
    } elseif (Ask-YesNo "Ensure SysMain is enabled and Automatic?" 'y') {
        try {
            Set-Service -Name "SysMain" -StartupType Automatic
            Start-Service -Name "SysMain" -ErrorAction SilentlyContinue
            Write-Host "  [+] SysMain enabled"
        } catch {
            Handle-Error -Context "Enabling SysMain service" -ErrorRecord $_
        }
    } else {
        Write-Host "  [ ] SysMain left unchanged."
    }
}

function Apply-PerformanceBaseline {
    param(
        [Parameter(Mandatory)]
        $HardwareProfile
    )

    Write-Section "Baseline performance adjustments"

    $prefetchPath = "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters"
    $prefetchValue = if ($HardwareProfile.HasSSD -and -not $HardwareProfile.HasHDD) { 1 } else { 3 }
    Set-RegistryValueSafe $prefetchPath "EnablePrefetcher" $prefetchValue
    Set-RegistryValueSafe $prefetchPath "EnableSuperfetch" $prefetchValue

    if ($HardwareProfile.MemoryCategory -eq 'Low') {
        Set-RegistryValueSafe "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" "VisualFXSetting" 2
        Write-Host "  [+] Animations/effects tuned for performance (RAM <6GB)."
    } else {
        Write-Host "  [ ] Animations left as-is (RAM >=6GB)."
    }

    Enable-UltimatePerformancePlan
}

function Enable-UltimatePerformancePlan {
    Write-Section "Enabling Ultimate Performance power plan"
    try {
        $guid = "e9a42b02-d5df-448d-aa00-03f14749eb61"
        powercfg -duplicatescheme $guid | Out-Null
    } catch { }

    try {
        powercfg -setactive $guid
        Write-Host "  [+] Ultimate Performance active."
    } catch {
        Handle-Error -Context "Activating Ultimate Performance power plan" -ErrorRecord $_
    }
}

Export-ModuleMember -Function Get-HardwareProfile, Get-OEMServiceInfo, Handle-SysMainPrompt, Apply-PerformanceBaseline, Enable-UltimatePerformancePlan
