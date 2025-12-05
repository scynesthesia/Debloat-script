# Nahue Windows Optimizer v0.1
# Pensado para 2 presets:
#   1) SOC / Main (seguro)
#   2) PC lenta / agresivo (incluye el 1 + tweaks extra)
# Ejecutar SIEMPRE como Administrador.

# ---------- COMPROBACIÓN ADMIN ----------
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[!] Ejecutá este script como administrador." -ForegroundColor Red
    Read-Host "Presioná Enter para salir"
    exit 1
}

# ---------- HELPERS ----------
function Write-Section {
    param([string]$Text)
    Write-Host ""
    Write-Host "========== $Text ==========" -ForegroundColor Cyan
}

function Ask-YesNo {
    param(
        [string]$Question,
        [string]$Default = 'n'
    )

    $defaultText = if ($Default -match '^[sSyY]$') { '[S/n]' } else { '[s/N]' }
    while ($true) {
        $resp = Read-Host "$Question $defaultText"
        if ([string]::IsNullOrWhiteSpace($resp)) { $resp = $Default }

        switch ($resp.ToLower()) {
            { $_ -in 's', 'y' } { return $true }
            { $_ -in 'n' } { return $false }
            default { Write-Host "  [!] Opción inválida. Respondé con s/n." -ForegroundColor Yellow }
        }
    }
}

function Read-MenuChoice {
    param(
        [string]$Prompt,
        [string[]]$ValidOptions
    )

    while ($true) {
        $choice = Read-Host $Prompt
        if ($ValidOptions -contains $choice) { return $choice }
        Write-Host "[!] Opción inválida" -ForegroundColor Yellow
    }
}

function Set-RegistryValueSafe {
    param(
        [string]$Path,
        [string]$Name,
        [object]$Value,
        [Microsoft.Win32.RegistryValueKind]$Type = [Microsoft.Win32.RegistryValueKind]::DWord
    )
    try {
        if (-not (Test-Path $Path)) {
            New-Item -Path $Path -Force | Out-Null
        }
        New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
    } catch {
        Write-Host "  [-] Error en $Path -> $Name : $_" -ForegroundColor Red
    }
}

# ---------- BLOCK: RESTORE POINT & LIMPIEZA ----------
function Create-RestorePointSafe {
    Write-Section "Creando punto de restauración"
    try {
        Checkpoint-Computer -Description "NahueOptimizer v0.1" -RestorePointType "MODIFY_SETTINGS"
        Write-Host "  [+] Punto de restauración creado."
    } catch {
        Write-Host "  [!] No se pudo crear (protección sistema desactivada?)" -ForegroundColor Yellow
    }
}

function Clear-TempFiles {
    Write-Section "Borrando archivos temporales básicos"
    $paths = @(
        "$env:TEMP",
        "$env:WINDIR\Temp"
    )

    foreach ($p in $paths) {
        if (Test-Path $p) {
            Write-Host "  [+] Limpiando $p"
            try {
                Get-ChildItem $p -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
            } catch {
                Write-Host "    [-] Error limpiando $p : $_" -ForegroundColor Yellow
            }
        }
    }

    # Limpieza básica de Windows Update cache (sin tocar cosas críticas)
    $wu = "$env:WINDIR\SoftwareDistribution\Download"
    if (Test-Path $wu) {
        Write-Host "  [+] Limpiando cache de Windows Update"
        try {
            Get-ChildItem $wu -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
        } catch {
            Write-Host "    [-] Error limpiando SoftwareDistribution : $_" -ForegroundColor Yellow
        }
    }
}

# ---------- BLOCK: PRIVACIDAD / TELEMETRÍA (SAFE) ----------
function Apply-PrivacyTelemetrySafe {
    Write-Section "Aplicando tweaks de privacidad / telemetría (preset SOC seguro)"

    # Disable Consumer Features (recomendaciones basura)
    Set-RegistryValueSafe "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableConsumerFeatures" 1

    # Telemetry a mínimo razonable
    Set-RegistryValueSafe "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "AllowTelemetry" 0

    # Activity History off
    $sysPol = "HKLM\SOFTWARE\Policies\Microsoft\Windows\System"
    Set-RegistryValueSafe $sysPol "EnableActivityFeed" 0
    Set-RegistryValueSafe $sysPol "PublishUserActivities" 0
    Set-RegistryValueSafe $sysPol "UploadUserActivities" 0

    # Location tracking off
    Set-RegistryValueSafe "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" "DisableLocation" 1

    # WiFi Sense off (legacy pero por las dudas)
    Set-RegistryValueSafe "HKLM\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" "AutoConnectAllowedOEM" 0

    # GameDVR off
    Set-RegistryValueSafe "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" "AllowGameDVR" 0
    Set-RegistryValueSafe "HKCU\System\GameConfigStore" "GameDVR_Enabled" 0
    Set-RegistryValueSafe "HKCU\System\GameConfigStore" "GameDVR_FSEBehaviorMode" 2

    # Bing en Start / Cortana (pregunta ligera)
    if (Ask-YesNo "¿Desactivar Cortana y búsquedas online en Start?" 's') {
        Set-RegistryValueSafe "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" "BingSearchEnabled" 0
        Set-RegistryValueSafe "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" "CortanaConsent" 0
        Write-Host "  [+] Cortana y Bing en Start desactivados"
    } else {
        Write-Host "  [ ] Cortana/Bing se mantienen como están."
    }

    # Storage Sense
    if (Ask-YesNo "¿Activar Storage Sense para limpieza automática básica?" 'n') {
        $storageSense = "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense"
        Set-RegistryValueSafe $storageSense "AllowStorageSenseGlobal" 1
        Set-RegistryValueSafe "$storageSense\Parameters\StoragePolicy" "01" 1
        Set-RegistryValueSafe "$storageSense\Parameters\StoragePolicy" "04" 1
        Write-Host "  [+] Storage Sense habilitado"
    } else {
        Write-Host "  [ ] Storage Sense sin cambios."
    }

    # Recomendaciones de apps y contenido en Start / Settings
    if (Ask-YesNo "¿Ocultar recomendaciones y contenido sugerido?" 's') {
        Set-RegistryValueSafe "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SystemPaneSuggestionsEnabled" 0
        Set-RegistryValueSafe "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SubscribedContent-338387Enabled" 0
        Set-RegistryValueSafe "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SubscribedContent-338388Enabled" 0
        Set-RegistryValueSafe "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SubscribedContent-338389Enabled" 0
        Set-RegistryValueSafe "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SubscribedContent-353694Enabled" 0
        Write-Host "  [+] Recomendaciones desactivadas"
    } else {
        Write-Host "  [ ] Recomendaciones se mantienen."
    }

    # Desactivar telemetría de PowerShell 7 (si existe)
    Set-RegistryValueSafe "HKLM\SOFTWARE\Microsoft\PowerShellCore\Telemetry" "EnableTelemetry" 0
}

function Clear-DeepTempAndThumbs {
    Write-Section "Limpieza extra (temp + miniaturas)"
    Clear-TempFiles

    $thumbDir = "$env:LOCALAPPDATA\Microsoft\Windows\Explorer"
    if (Test-Path $thumbDir) {
        Write-Host "  [+] Borrando caché de miniaturas"
        try {
            Get-ChildItem $thumbDir -Filter "thumbcache_*" -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
        } catch {
            Write-Host "    [-] No se pudo limpiar miniaturas: $_" -ForegroundColor Yellow
        }
    }
}

# ---------- BLOCK: DEBLOAT LIGHT (sin romper nada importante) ----------
function Apply-DebloatSafe {
    Write-Section "Debloat seguro (apps basura típicas, no toca Store ni cosas críticas)"

    $apps = @(
        "Microsoft.BingNews",
        "Microsoft.BingWeather",
        "Microsoft.GetHelp",
        "Microsoft.Getstarted",
        "Microsoft.Microsoft3DViewer",
        "Microsoft.MicrosoftSolitaireCollection",
        "Microsoft.MixedReality.Portal",
        "Microsoft.Xbox.TCUI",
        "Microsoft.XboxApp",
        "Microsoft.XboxGameOverlay",
        "Microsoft.XboxGamingOverlay",
        "Microsoft.XboxIdentityProvider",
        "Microsoft.XboxSpeechToTextOverlay"
    )

    foreach ($a in $apps) {
        $pkg = Get-AppxPackage -AllUsers -Name $a -ErrorAction SilentlyContinue
        if ($pkg) {
            Write-Host "  [+] Quitando $a"
            try {
                Get-AppxPackage -AllUsers -Name $a | Remove-AppxPackage -ErrorAction SilentlyContinue
            } catch {
                Write-Host "    [-] Error quitando $a : $_" -ForegroundColor Yellow
            }
        } else {
            Write-Host "  [ ] $a no está instalado."
        }
    }
}

# ---------- BLOCK: PREFERENCIAS / UX SEGURAS ----------
function Apply-PreferencesSafe {
    Write-Section "Ajustando preferencias de UX (Start, Explorer, etc.)"

    # Mostrar archivos ocultos
    Set-RegistryValueSafe "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "Hidden" 1
    # Mostrar extensiones
    Set-RegistryValueSafe "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "HideFileExt" 0

    # Desactivar Mouse Acceleration
    Set-RegistryValueSafe "HKCU\Control Panel\Mouse" "MouseSpeed" 0
    Set-RegistryValueSafe "HKCU\Control Panel\Mouse" "MouseThreshold1" 0
    Set-RegistryValueSafe "HKCU\Control Panel\Mouse" "MouseThreshold2" 0

    # Desactivar Sticky Keys
    Set-RegistryValueSafe "HKCU\Control Panel\Accessibility\StickyKeys" "Flags" 506

    # Clásico menú contextual (Windows 11)
    Set-RegistryValueSafe "HKCU\SOFTWARE\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" "" "" ([Microsoft.Win32.RegistryValueKind]::String)

    # Mostrar iconos útiles en Explorer
    # (Quita "Home" de la barra lateral)
    Set-RegistryValueSafe "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "LaunchTo" 1

    # Detailed BSOD
    Set-RegistryValueSafe "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl" "DisplayParameters" 1

    # NumLock on
    Set-RegistryValueSafe "HKCU\Control Panel\Keyboard" "InitialKeyboardIndicators" 2147483650
}

function Handle-SysMainPrompt {
    Write-Section "SysMain (Superfetch)"
    Write-Host "SysMain acelera lanzamientos y prefetch, pero puede usar disco/CPU en equipos lentos." -ForegroundColor Gray
    if (Ask-YesNo "¿Querés desactivar SysMain para priorizar recursos?" 'n') {
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

# ---------- BLOCK: PERFORMANCE PLAN ----------
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

# ---------- BLOCK: TWEAKS AGRESIVOS (PC LENTA) ----------
function Apply-AggressiveTweaks {
    Write-Section "Tweaks adicionales para PC lenta (más agresivo)"

    # Desactivar hibernación (bueno para desktop - ojo laptops)
    Write-Host "  [+] Desactivando hibernación"
    try {
        powercfg -h off
    } catch {
        Write-Host "    [-] Error desactivando hibernación: $_" -ForegroundColor Yellow
    }

    # Desactivar apps en segundo plano
    Write-Host "  [+] Bloqueando apps en segundo plano"
    Set-RegistryValueSafe "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" "LetAppsRunInBackground" 2

    # Debloat un poco más agresivo (sin romper Edge/Store)
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
                Write-Host "      [-] Error quitando $a : $_" -ForegroundColor Yellow
            }
        }
    }

    # Servicio Print Spooler
    if (Ask-YesNo "¿Desactivar Print Spooler si no usás impresoras?" 'n') {
        try {
            Stop-Service -Name "Spooler" -ErrorAction SilentlyContinue
            Set-Service -Name "Spooler" -StartupType Disabled
            Write-Host "  [+] Print Spooler desactivado"
        } catch {
            Write-Host "    [-] No se pudo desactivar Spooler: $_" -ForegroundColor Yellow
        }
    }

    # OneDrive auto-start
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

    # Tareas de Consumer Experience / CEIP
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

    # Limpieza adicional
    Clear-DeepTempAndThumbs

    # Opcional: quitar OneDrive
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

# ---------- PRESETS ----------

function Run-SOCPreset {
    Write-Section "Preset 1: SOC / Main (seguro)"
    Create-RestorePointSafe
    Clear-TempFiles
    Apply-PrivacyTelemetrySafe
    Apply-DebloatSafe
    Apply-PreferencesSafe
    Handle-SysMainPrompt
    Enable-UltimatePerformancePlan
    Write-Host ""
    Write-Host "[+] Preset SOC / Main aplicado. Reiniciá el sistema cuando puedas." -ForegroundColor Green
}

function Run-PCSlowPreset {
    Write-Section "Preset 2: PC Lenta / Agresivo"
    Create-RestorePointSafe
    Clear-TempFiles
    Apply-PrivacyTelemetrySafe
    Apply-DebloatSafe
    Apply-PreferencesSafe
    Enable-UltimatePerformancePlan
    Apply-AggressiveTweaks
    Write-Host ""
    Write-Host "[+] Preset PC Lenta / Agresivo aplicado. Reiniciá el sistema." -ForegroundColor Green
}

# ---------- MENÚ PRINCIPAL ----------

do {
    Clear-Host
    Write-Host "===== Nahue Optimizer v0.1 =====" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "1) Aplicar Preset SOC / Main (seguro)"
    Write-Host "2) Aplicar Preset PC Lenta / Agresivo"
    Write-Host "0) Salir"
    Write-Host ""
    $choice = Read-MenuChoice "Elegí una opción" @('1','2','0')

    switch ($choice) {
        '1' { Run-SOCPreset }
        '2' { Run-PCSlowPreset }
        '0' { break }
    }

    if ($choice -ne '0') {
        Write-Host ""
        Read-Host "Presioná Enter para volver al menú"
    }
} while ($true)
