# Scynesthesia Windows Optimizer v0.1
# Run this script as Administrator.

# ---------- 1. ADMIN CHECK ----------
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[!] Run this script as Administrator." -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

# ---------- 2. MODULE IMPORTS (MOVIDO ARRIBA PARA EVITAR ERRORES) ----------
$ScriptPath = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Definition }
try {
    $moduleFiles = @(
        'ui.psm1',
        'privacy.psm1',
        'debloat.psm1',
        'performance.psm1',
        'aggressive.psm1',
        'repair.psm1',
        'gaming.psm1'
    )

    $modulesRoot = Join-Path $ScriptPath 'modules'
    foreach ($module in $moduleFiles) {
        $modulePath = Join-Path $modulesRoot $module
        Import-Module $modulePath -Force -ErrorAction Stop
    }

    Write-Host "Modules loaded successfully." -ForegroundColor Green
} catch {
    if (Get-Command Handle-Error -ErrorAction SilentlyContinue) {
        Handle-Error -Context "Loading modules" -ErrorRecord $_
    } else {
        Write-Error "Error loading modules: $($_.Exception.Message)"
    }
    Write-Host "Make sure the 'modules' folder is next to this script."
    Read-Host "Press Enter to exit"
    exit 1
}

# ---------- 3. LOGGING (AHORA SÍ FUNCIONA) ----------
$TranscriptStarted = $false
# Ahora Ask-YesNo ya existe porque importamos ui.psm1 arriba
if (Ask-YesNo "Enable session logging to a file? (Recommended for Service Records) [y/N]" 'n') {
    $logDir = Join-Path $env:TEMP "ScynesthesiaOptimizer"
    if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
    
    $timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
    $logFile = Join-Path $logDir "Scynesthesia_Log_$timestamp.txt"
    
    try {
        Start-Transcript -Path $logFile -Append -ErrorAction Stop
        $TranscriptStarted = $true
        Write-Host "Logging started: $logFile" -ForegroundColor Gray
    } catch {
        Write-Warning "Could not start logging. Check permissions."
    }
}

# ---------- 4. LOCAL FUNCTIONS ----------

function Show-Banner {
    Clear-Host
    $banner = @'

 _____                                                                _____ 
( ___ )--------------------------------------------------------------( ___ )
 |   |                                                                |   | 
 |   |                                  _   _               _         |   | 
 |   |   ___  ___ _   _ _ __   ___  ___| |_| |__   ___  ___(_) __ _   |   | 
 |   |  / __|/ __| | | | '_ \ / _ \/ __| __| '_ \ / _ \/ __| |/ _` |  |   | 
 |   |  \__ \ (__| |_| | | | |  __/\__ \ |_| | | |  __/\__ \ | (_| |  |   | 
 |   |  |___/\___|\__, |_| |_|\___||___/\__|_| |_|\___||___/_|\__,_|  |   | 
 |   |       _    |___/   _             _                             |   | 
 |   |    __| | ___| |__ | | ___   __ _| |_ ___ _ __                  |   | 
 |   |   / _` |/ _ \ '_ \| |/ _ \ / _` | __/ _ \ '__|                 |   | 
 |   |  | (_| |  __/ |_) | | (_) | (_| | ||  __/ |                    |   | 
 |   |   \__,_|\___|_.__/|_|\___/ \__,_|\__\___|_|                    |   | 
 |   |                                                                |   | 
 |___|                                                                |___| 
(_____)--------------------------------------------------------------(_____)

'@
    Write-Host $banner -ForegroundColor Magenta
    Write-Host " Scynesthesia Windows Optimizer" -ForegroundColor Green
    Write-Host " Preset 1: Safe | Preset 2: Slow PC / Aggressive" -ForegroundColor Gray
    Write-Host " Base power plan: High performance" -ForegroundColor Yellow
    Write-Host "------------------------------------------------------------`n" -ForegroundColor DarkGray
}

function Ensure-PowerPlan {
    param([ValidateSet('Balanced','HighPerformance')][string]$Mode = 'HighPerformance')
    Write-Host "  [i] Setting base power plan to: $Mode" -ForegroundColor Gray
    if ($Mode -eq 'HighPerformance') {
        powercfg /setactive SCHEME_MIN
    } else {
        powercfg /setactive SCHEME_BALANCED
    }
}

function Invoke-SafeOptionalPrompts {
    Write-Section "Additional options for Safe preset"
    $options = @(
        @{ Key = '1'; Description = 'Disable Cortana in search'; Action = { Set-RegistryValueSafe "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "AllowCortana" 0 } },
        @{ Key = '2'; Description = 'Disable Store suggestions in Start'; Action = { Set-RegistryValueSafe "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SilentInstalledAppsEnabled" 0 } },
        @{ Key = '3'; Description = 'Enable compact view in File Explorer'; Action = { Set-RegistryValueSafe "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "UseCompactMode" 1 } }
    )
    foreach ($opt in $options) {
        if (Ask-YesNo -Question "$($opt.Key)) $($opt.Description)" -Default 'n') {
            & $opt.Action
            Write-Host "✔ $($opt.Description) applied." -ForegroundColor Green
        } else {
            Write-Host "Skipped: $($opt.Description)." -ForegroundColor DarkGray
        }
    }
}

# ---------- 5. PRESETS ----------

function Run-SafePreset {
    $Status = @{ PackagesFailed = @(); RebootRequired = $false }
    $HWProfile = Get-HardwareProfile

    Write-Section "Starting Preset 1: Safe (Main)"
    Create-RestorePointSafe
    Clear-TempFiles

    # Safe Debloat (Standard list)
    Apply-PrivacyTelemetrySafe
    $debloatResult = Apply-DebloatSafe # Usa la lista por defecto definida en el módulo
    $Status.PackagesFailed += $debloatResult.Failed

    Apply-PreferencesSafe
    Invoke-SafeOptionalPrompts
    Handle-SysMainPrompt -HardwareProfile $HWProfile
    Apply-PerformanceBaseline -HardwareProfile $HWProfile
    Ensure-PowerPlan -Mode 'HighPerformance'

    $Status.RebootRequired = $true
    Write-OutcomeSummary -Status $Status
    Write-Host "[+] Safe preset applied. Restart when possible." -ForegroundColor Green
}

function Run-PCSlowPreset {
    $Status = @{ PackagesFailed = @(); RebootRequired = $false }
    $HWProfile = Get-HardwareProfile
    $OemServices = Get-OEMServiceInfo

    Write-Section "Starting Preset 2: Slow PC / Aggressive"
    Create-RestorePointSafe
    Clear-TempFiles

    Apply-PrivacyTelemetrySafe
    
    # AQUI ESTA EL CAMBIO: Usamos Apply-DebloatAggressive para limpieza profunda
    # Esto usa la nueva funcion que creaste en debloat.psm1
    $debloatResult = Apply-DebloatAggressive 
    $Status.PackagesFailed += $debloatResult.Failed
    
    Apply-PreferencesSafe
    Apply-PerformanceBaseline -HardwareProfile $HWProfile
    Ensure-PowerPlan -Mode 'HighPerformance'

    # Tweaks adicionales especificos de PC lenta
    Apply-AggressiveTweaks -HardwareProfile $HWProfile -FailedPackages ([ref]$Status.PackagesFailed) -OemServices $OemServices

    $Status.RebootRequired = $true
    Write-OutcomeSummary -Status $Status
    Write-Host "[+] Slow PC / Aggressive preset applied. Please restart." -ForegroundColor Green
}

# ---------- 6. MAIN LOOP ----------

do {
    Show-Banner
    Write-Host "1) Apply Safe preset (Main)"
    Write-Host "2) Apply Slow PC / Aggressive preset"
    Write-Host "3) GAMING MODE / FPS BOOST (Add-on)"
    Write-Host "4) Repair Tools"
    Write-Host "0) Exit"
    Write-Host ""
    $choice = Read-MenuChoice "Select an option" @('1','2','3','4','0')

    switch ($choice) {
        '1' { Run-SafePreset }
        '2' { Run-PCSlowPreset }
        '3' {
            Write-Section "GAMING MODE / FPS BOOST"
            Optimize-NetworkLatency
            Optimize-GamingScheduler
            Apply-CustomGamingPowerSettings
            Optimize-ProcessorScheduling 
            Enable-MsiModeSafe
            Write-Host "[+] Gaming tweaks applied." -ForegroundColor Magenta
        }
        '4' {
            Write-Section "Repair Tools"
            Invoke-NetworkSoftReset
            Invoke-SystemRepair
        }
        '0' { break }
    }

    if ($choice -ne '0') {
        Write-Host ""
        Read-Host "Press Enter to return to the menu"
    }
} while ($choice -ne '0')

try {
    if ($TranscriptStarted) {
        Stop-Transcript | Out-Null
        Write-Host "Log saved." -ForegroundColor Gray
    }
} catch {}
