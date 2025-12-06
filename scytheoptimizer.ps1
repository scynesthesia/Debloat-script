# Nahue Windows Optimizer v0.1
# Ejecutar SIEMPRE como Administrador.

# ---------- 1. COMPROBACIÓN ADMIN ----------
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[!] Ejecutá este script como administrador." -ForegroundColor Red
    Read-Host "Presioná Enter para salir"
    exit 1
}

# ---------- 2. IMPORTACIÓN DE MÓDULOS ----------
# Esto reemplaza las cientos de líneas que tenías copiadas.
# Carga las funciones desde los archivos en la carpeta /modules.
$ScriptPath = $PSScriptRoot
try {
    Import-Module "$ScriptPath\modules\ui.psm1" -Force -ErrorAction Stop
    Import-Module "$ScriptPath\modules\privacy.psm1" -Force -ErrorAction Stop
    Import-Module "$ScriptPath\modules\debloat.psm1" -Force -ErrorAction Stop
    Import-Module "$ScriptPath\modules\performance.psm1" -Force -ErrorAction Stop
    Import-Module "$ScriptPath\modules\aggressive.psm1" -Force -ErrorAction Stop
    Write-Host "Módulos cargados correctamente." -ForegroundColor Green
} catch {
    Write-Host "Error cargando módulos: $_" -ForegroundColor Red
    Write-Host "Asegurate de que la carpeta 'modules' esté junto a este script."
    Read-Host "Presioná Enter para salir"
    exit 1
}

# ---------- 3. FUNCIONES LOCALES (Solo lógica visual y de menú) ----------

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
}

function Ensure-PowerPlan {
    param(
        [ValidateSet('Balanced','HighPerformance')][string]$Mode = 'HighPerformance'
    )
    Write-Host "  [i] Ajustando plan de energía a: $Mode" -ForegroundColor Gray
    if ($Mode -eq 'HighPerformance') {
        powercfg /setactive SCHEME_MIN
    } else {
        powercfg /setactive SCHEME_BALANCED
    }
}

function Invoke-SOCOptionalPrompts {
    Write-Section "Opciones adicionales para SOC"

    $options = @(
        @{ Key = '1'; Description = 'Desactivar Cortana en búsqueda'; Action = { Set-RegistryValueSafe "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "AllowCortana" 0 } },
        @{ Key = '2'; Description = 'Desactivar sugerencias de la Tienda en Inicio'; Action = { Set-RegistryValueSafe "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SilentInstalledAppsEnabled" 0 } },
        @{ Key = '3'; Description = 'Habilitar vista compacta en el Explorador'; Action = { Set-RegistryValueSafe "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "UseCompactMode" 1 } }
    )

    foreach ($opt in $options) {
        # Usamos Ask-YesNo que ahora viene importado de ui.psm1
        if (Ask-YesNo "$($opt.Key)) $($opt.Description)" 'n') {
            & $opt.Action
            Write-Host "✔ $($opt.Description) aplicado." -ForegroundColor Green
        } else {
            Write-Host "Omitido: $($opt.Description)." -ForegroundColor DarkGray
        }
    }
}

# ---------- 4. PRESETS (Lógica de orquestación) ----------

function Run-SOCPreset {
    $Status = @{ PackagesFailed = @(); RebootRequired = $false }
    # Detectar Hardware (viene de performance.psm1)
    $HWProfile = Get-HardwareProfile
    
    Write-Section "Iniciando Preset 1: SOC / Main (Seguro)"
    
    # Estas funciones vienen de debloat.psm1
    Create-RestorePointSafe
    Clear-TempFiles
    
    # Privacidad (privacy.psm1) y Debloat
    Apply-PrivacyTelemetrySafe
    $debloatResult = Apply-DebloatSafe
    $Status.PackagesFailed += $debloatResult.Failed
    
    # Preferencias (privacy.psm1) y Extras
    Apply-PreferencesSafe
    Invoke-SOCOptionalPrompts
    
    # Rendimiento (performance.psm1)
    Handle-SysMainPrompt -HardwareProfile $HWProfile
    Apply-PerformanceBaseline -HardwareProfile $HWProfile
    Ensure-PowerPlan -Mode 'HighPerformance'

    $Status.RebootRequired = $true
    
    # Resumen (ui.psm1)
    Write-OutcomeSummary -Status $Status
    Write-Host "[+] Preset SOC / Main aplicado. Reiniciá el sistema cuando puedas." -ForegroundColor Green
}

function Run-PCSlowPreset {
    $Status = @{ PackagesFailed = @(); RebootRequired = $false }
    $HWProfile = Get-HardwareProfile
    $OemServices = Get-OEMServiceInfo

    Write-Section "Iniciando Preset 2: PC Lenta / Agresivo"
    
    Create-RestorePointSafe
    Clear-TempFiles
    
    # Base SOC
    Apply-PrivacyTelemetrySafe
    $debloatResult = Apply-DebloatSafe
    $Status.PackagesFailed += $debloatResult.Failed
    Apply-PreferencesSafe
    
    # Rendimiento Aggressive
    Apply-PerformanceBaseline -HardwareProfile $HWProfile
    Ensure-PowerPlan -Mode 'HighPerformance'
    
    # Tweaks Agresivos (aggressive.psm1)
    Apply-AggressiveTweaks -HardwareProfile $HWProfile -FailedPackages ([ref]$Status.PackagesFailed) -OemServices $OemServices
    
    $Status.RebootRequired = $true

    Write-OutcomeSummary -Status $Status
    Write-Host "[+] Preset PC Lenta / Agresivo aplicado. Reiniciá el sistema." -ForegroundColor Green
}

# ---------- 5. BUCLE PRINCIPAL (MENÚ) ----------

do {
    Show-Banner
    Write-Host "1) Aplicar Preset SOC / Main (Seguro)"
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
} while ($choice -ne '0')
