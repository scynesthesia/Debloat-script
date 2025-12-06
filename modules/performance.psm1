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
    $hint = if ($HardwareProfile.HasHDD -and -not $HardwareProfile.HasSSD) { 'HDD detectado: SysMain puede acelerar lanzamientos.' } else { 'SSD detectado: podés desactivarlo para evitar IO extra.' }
    Write-Host $hint -ForegroundColor Gray

    $defaultChoice = if ($HardwareProfile.HasSSD -and -not $HardwareProfile.HasHDD) { 's' } else { 'n' }
    if (Ask-YesNo "¿Querés desactivar SysMain para priorizar recursos?" $defaultChoice) {
        try {
            Stop-Service -Name "SysMain" -ErrorAction SilentlyContinue
            Set-Service -Name "SysMain" -StartupType Disabled
            Write-Host "  [+] SysMain desactivado"
        } catch {
            Write-Host "  [-] No se pudo ajustar SysMain: $_" -ForegroundColor Yellow
        }
    } elseif (Ask-YesNo "¿Asegurar SysMain activo y en Automático?" 's') {
        try {
            Set-Service -Name "SysMain" -StartupType Automatic
            Start-Service -Name "SysMain" -ErrorAction SilentlyContinue
            Write-Host "  [+] SysMain habilitado"
        } catch {
            Write-Host "  [-] No se pudo habilitar SysMain: $_" -ForegroundColor Yellow
        }
    } else {
        Write-Host "  [ ] SysMain sin cambios."
    }
}

function Apply-PerformanceBaseline {
    param(
        [Parameter(Mandatory)]
        $HardwareProfile
    )

    Write-Section "Ajustes base de rendimiento"

    $prefetchPath = "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters"
    $prefetchValue = if ($HardwareProfile.HasSSD -and -not $HardwareProfile.HasHDD) { 1 } else { 3 }
    Set-RegistryValueSafe $prefetchPath "EnablePrefetcher" $prefetchValue
    Set-RegistryValueSafe $prefetchPath "EnableSuperfetch" $prefetchValue

    if ($HardwareProfile.MemoryCategory -eq 'Low') {
        Set-RegistryValueSafe "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" "VisualFXSetting" 2
        Write-Host "  [+] Animaciones/efectos ajustados a mejor rendimiento (RAM <6GB)."
    } else {
        Write-Host "  [ ] Animaciones se mantienen (RAM >=6GB)."
    }

    Enable-UltimatePerformancePlan
}

function Enable-UltimatePerformancePlan {
    Write-Section "Activando Ultimate Performance power plan"
    try {
        $guid = "e9a42b02-d5df-448d-aa00-03f14749eb61"
        powercfg -duplicatescheme $guid | Out-Null
    } catch { }

    try {
        powercfg -setactive $guid
        Write-Host "  [+] Ultimate Performance activo."
    } catch {
        Write-Host "  [!] No se pudo activar Ultimate Performance: $_" -ForegroundColor Yellow
    }
}

Export-ModuleMember -Function Get-HardwareProfile, Get-OEMServiceInfo, Handle-SysMainPrompt, Apply-PerformanceBaseline, Enable-UltimatePerformancePlan
