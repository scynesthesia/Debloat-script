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

function Show-Banner {
    Clear-Host
    $banner = @'
   _____                 _   _           ____        _              _
  / ____|               | | (_)         |  _ \      | |            | |
 | (___  _   _ _ __   __| |  _  ___ ___ | |_) | ___ | |_ ___   ___ | |_ ___  _ __
  \___ \| | | | '_ \ / _` | | |/ __/ __||  _ < / _ \| __/ _ \ / _ \| __/ _ \| '__|
  ____) | |_| | | | | (_| | | | (__\__ \| |_) | (_) | || (_) | (_) | || (_) | |
 |_____/ \__, |_| |_|\__,_| |_|\___|___/|____/ \___/ \__\___/ \___/ \__\___/|_|
          __/ |
         |___/                                
'@
    Write-Host $banner -ForegroundColor Magenta
    Write-Host " Optimización segura y clara" -ForegroundColor Green
    Write-Host " Preset 1: SOC / Main  |  Preset 2: PC Lenta / Agresivo" -ForegroundColor Gray
    Write-Host " Power plan base: Alto rendimiento" -ForegroundColor Yellow
    Write-Host "------------------------------------------------------------`n" -ForegroundColor DarkGray
function Write-Section($Title) {
    Write-Host "`n==== $Title ====``n" -ForegroundColor Cyan
}

function Set-PolicyValue {
    param(
        [string]$Question,
        [string]$Default = 'n'
    )

    $defaultText = if ($Default -match '^[sSyY]$') { '[S/n]' } else { '[s/N]' }
    while ($true) {
        $resp = Read-Host "$Question $defaultText"
        if ([string]::IsNullOrWhiteSpace($resp)) { $resp = $Default }

function Ask-YesNo {
    param(
        [string]$Prompt,
        [string]$Default = '0'
    )

    $answer = Read-Host "$Prompt (1 = Sí, 0 = No) [Predeterminado: $Default]"
    if ([string]::IsNullOrWhiteSpace($answer)) {
        $answer = $Default
    }
    return $answer -eq '1'
}

function Initialize-RestorePoint {
    Write-Section "Punto de restauración"
    Write-Host "Creando punto de restauración inicial (MODIFY_SETTINGS)..." -ForegroundColor Gray
    try {
        Checkpoint-Computer -Description "ScytheOptimizer-PreRun" -RestorePointType "MODIFY_SETTINGS"
        Write-Host "Punto de restauración creado correctamente." -ForegroundColor Green
    } catch {
        Write-Warning "No se pudo crear el punto de restauración. Verifica que la Protección del sistema esté habilitada."
    }
}

# ---------- STATUS TRACKING ----------
$status = @{ PackagesFailed = @(); RebootRequired = $false }

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

function Invoke-SOCOptionalPrompts {
    Write-Section "Opciones adicionales para SOC"

    $options = @(
        @{ Key = '1'; Description = 'Desactivar Cortana en búsqueda'; Action = { Set-PolicyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Value 0 } },
        @{ Key = '2'; Description = 'Desactivar sugerencias de la Tienda en Inicio'; Action = { Set-PolicyValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SilentInstalledAppsEnabled" -Value 0 } },
        @{ Key = '3'; Description = 'Activar Storage Sense de forma mensual'; Action = { Set-PolicyValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Name "01" -Value 1; Set-PolicyValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Name "2048" -Value 30 } },
        @{ Key = '4'; Description = 'Reducir frecuencia de Feedback a Nunca'; Action = { Set-PolicyValue -Path "HKCU:\Software\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Value 0; Set-PolicyValue -Path "HKCU:\Software\Microsoft\Siuf\Rules" -Name "PeriodInNanoSeconds" -Type QWord -Value 0 } },
        @{ Key = '5'; Description = 'Habilitar vista compacta en el Explorador'; Action = { Set-PolicyValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "UseCompactMode" -Value 1 } }
    )

    foreach ($opt in $options) {
        $apply = Ask-YesNo "$($opt.Key)) $($opt.Description)"
        if ($apply) {
            & $opt.Action
            Write-Host "✔ $($opt.Description) aplicado." -ForegroundColor Green
        } else {
            Write-Host "Omitido: $($opt.Description)." -ForegroundColor DarkGray
        }
    }
}

function Apply-SOCProfile {
    param(
        [ValidateSet('Balanced','HighPerformance','Ultimate')][string]$Mode = 'HighPerformance'
function Ensure-PowerPlan {
    param(
        $HardwareProfile,
        [ref]$StatusRef
    )

    Write-Section "Preset 1: SOC / Main (seguro)"
    Create-RestorePointSafe
    Clear-TempFiles
    Apply-PrivacyTelemetrySafe
    Apply-PrivacyHardeningExtra
    $debloat = Apply-DebloatSafe
    $StatusRef.Value.PackagesFailed += $debloat.Failed
    Apply-PreferencesSafe
    Handle-SysMainPrompt -HardwareProfile $HardwareProfile
    Apply-PerformanceBaseline -HardwareProfile $HardwareProfile
    Ensure-PowerPlan -Mode 'HighPerformance'

    Write-Section "Preset 1: SOC / Main (seguro)"
    Create-RestorePointSafe
    Clear-TempFiles
    Apply-PrivacyTelemetrySafe
    Apply-PrivacyHardeningExtra
    $debloat = Apply-DebloatSafe
    $StatusRef.Value.PackagesFailed += $debloat.Failed
    Apply-PreferencesSafe
    Handle-SysMainPrompt -HardwareProfile $HardwareProfile
    Apply-PerformanceBaseline -HardwareProfile $HardwareProfile

    $StatusRef.Value.RebootRequired = $true
    Write-Host ""
    Write-Host "[+] Preset SOC / Main aplicado. Reiniciá el sistema cuando puedas." -ForegroundColor Green
    Write-OutcomeSummary -Status $StatusRef.Value
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

function Apply-SOCProfile {
    Write-Section "Aplicando preset SOC / Main"
    Invoke-PrivacyTelemetrySafe
    Invoke-DebloatSafe
    Invoke-PreferencesSafe
    Invoke-SOCOptionalPrompts
    Ensure-PowerPlan -Mode 'HighPerformance'
    Ensure-PowerPlan -Mode 'HighPerformance'
    Set-PowerPlan -Mode 'Balanced'
    Write-Host "Preset SOC / Main completado."
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
