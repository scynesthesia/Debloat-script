function Optimize-NetworkLatency {
    Write-Section "Optimización de Latencia (Ping/Jitter)"
    Write-Host "Recomendado para juegos online competitivos (Valorant, CS2, CoD)." -ForegroundColor Gray
    
    if (Ask-YesNo "¿Desactivar Network Throttling y optimizar respuesta de red?" 's') {
        # Network Throttling + SystemResponsiveness
        Set-RegistryValueSafe "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" "NetworkThrottlingIndex" 0xffffffff
        Set-RegistryValueSafe "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" "SystemResponsiveness" 0

        # Nagle / TCP a nivel interfaz
        $tcpParams  = "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"
        $interfaces = Get-ChildItem $tcpParams -ErrorAction SilentlyContinue
        foreach ($iface in $interfaces) {
            Set-RegistryValueSafe $iface.PSPath "TcpAckFrequency" 1
            Set-RegistryValueSafe $iface.PSPath "TCPNoDelay" 1
        }

        Write-Host "  [+] Red optimizada para latencia ultra-baja." -ForegroundColor Green
    } else {
        Write-Host "  [ ] Tweaks de red omitidos." -ForegroundColor DarkGray
    }
}

function Optimize-GamingScheduler {
    Write-Section "Prioridad de Procesos (Gaming)"

    if (Ask-YesNo "¿Priorizar GPU/CPU para juegos en primer plano?" 's') {
        $gamesPath = "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"

        Set-RegistryValueSafe $gamesPath "GPU Priority" 8
        Set-RegistryValueSafe $gamesPath "Priority" 6
        Set-RegistryValueSafe $gamesPath "Scheduling Category" "High" ([Microsoft.Win32.RegistryValueKind]::String)
        Set-RegistryValueSafe $gamesPath "SFIO Priority" "High" ([Microsoft.Win32.RegistryValueKind]::String)

        # Ya dejamos SystemResponsiveness en 0 en Optimize-NetworkLatency
        Write-Host "  [+] Programador optimizado para juegos." -ForegroundColor Green
    } else {
        Write-Host "  [ ] Programador sin cambios." -ForegroundColor DarkGray
    }
}

function Apply-CustomGamingPowerSettings {
    Write-Section "Power Plan: 'Custom Gaming Tweaks'"

    $isLaptop = Get-CimInstance -ClassName Win32_Battery -ErrorAction SilentlyContinue
    if ($isLaptop) {
        Write-Host "  [!] Portátil detectada: estos ajustes suben consumo y temperatura." -ForegroundColor Yellow
        Write-Host "      Recomendado usarlos sólo con el cargador conectado (CA)." -ForegroundColor Yellow
    }

    Write-Host "Aplicando ajustes sobre el plan ACTUAL (SCHEME_CURRENT)." -ForegroundColor DarkGray

    if (Ask-YesNo "¿Aplicar tweaks de energía hardcore para priorizar FPS?" 'n') {
        try {
            # 1) Discos / NVMe
            powercfg /setacvalueindex SCHEME_CURRENT SUB_DISK DISKIDLE 0
            powercfg /setacvalueindex SCHEME_CURRENT SUB_DISK 0b2d69d7-a2a1-449c-9680-f91c70521c60 0

            # 2) CPU / Core parking / EPP
            powercfg /setacvalueindex SCHEME_CURRENT SUB_PROCESSOR PROCTHROTTLEMIN 100
            powercfg /setacvalueindex SCHEME_CURRENT SUB_PROCESSOR 0cc5b647-c1df-4637-891a-dec35c318583 100
            powercfg /setacvalueindex SCHEME_CURRENT SUB_PROCESSOR 36687f9e-e3a5-4dbf-b1dc-15eb381c6863 0

            # 3) USB selective suspend OFF
            powercfg /setacvalueindex SCHEME_CURRENT `
                2a737441-1930-4402-8d77-b2bebba308a3 `
                48e6b7a6-50f5-4782-a5d4-53bb8f07e226 0

            # 4) PCIe Link State OFF
            powercfg /setacvalueindex SCHEME_CURRENT `
                501a4d13-42af-4429-9fd1-a8218c268e20 `
                ee12f906-d277-404b-b6da-e5fa1a576df5 0

            powercfg /setactive SCHEME_CURRENT

            Write-Host "  [+] Ajustes de energía para gaming aplicados." -ForegroundColor Green
        } catch {
            Write-Host "  [-] Error aplicando ajustes de energía: $_" -ForegroundColor Yellow
        }
    } else {
        Write-Host "  [ ] Ajustes de energía hardcore omitidos." -ForegroundColor DarkGray
    }
}

Export-ModuleMember -Function Optimize-NetworkLatency, Optimize-GamingScheduler, Apply-CustomGamingPowerSettings
