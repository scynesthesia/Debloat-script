# Scynesthesia Windows Optimizer v0.1
# Run this script as Administrator.

# ---------- 1. ADMIN CHECK ----------
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[!] Run this script as Administrator." -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

# ---------- 2. MODULE IMPORTS ----------
# Load functions from the files in the /modules folder.
$ScriptPath = $PSScriptRoot
try {
    Import-Module "$ScriptPath\modules\ui.psm1" -Force -ErrorAction Stop
    Import-Module "$ScriptPath\modules\privacy.psm1" -Force -ErrorAction Stop
    Import-Module "$ScriptPath\modules\debloat.psm1" -Force -ErrorAction Stop
    Import-Module "$ScriptPath\modules\performance.psm1" -Force -ErrorAction Stop
    Import-Module "$ScriptPath\modules\aggressive.psm1" -Force -ErrorAction Stop
    Import-Module "$ScriptPath\modules\repair.psm1" -Force -ErrorAction Stop
    Import-Module "$ScriptPath\modules\gaming.psm1" -Force -ErrorAction Stop
    Write-Host "Modules loaded successfully." -ForegroundColor Green
} catch {
    Write-Host "Error loading modules: $_" -ForegroundColor Red
    Write-Host "Make sure the 'modules' folder is next to this script."
    Read-Host "Press Enter to exit"
    exit 1
}

# ---------- 3. LOCAL FUNCTIONS (Menu + visuals) ----------

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
    Write-Host " Safe optimization, clear choices" -ForegroundColor Green
    Write-Host " Preset 1: Safe / Main  |  Preset 2: Slow PC / Aggressive" -ForegroundColor Gray
    Write-Host " Base power plan: High performance" -ForegroundColor Yellow
    Write-Host "------------------------------------------------------------`n" -ForegroundColor DarkGray
}

function Ensure-PowerPlan {
    param(
        [ValidateSet('Balanced','HighPerformance')][string]$Mode = 'HighPerformance'
    )
    Write-Host "  [i] Setting power plan to: $Mode" -ForegroundColor Gray
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
        # Uses Ask-YesNo imported from ui.psm1
        if (Ask-YesNo -Question "$($opt.Key)) $($opt.Description)" -Default 'n') {
            & $opt.Action
            Write-Host "✔ $($opt.Description) applied." -ForegroundColor Green
        } else {
            Write-Host "Skipped: $($opt.Description)." -ForegroundColor DarkGray
        }
    }
}

# ---------- 4. PRESETS (Orchestration) ----------

function Run-SafePreset {
    $Status = @{ PackagesFailed = @(); RebootRequired = $false }
    # Detect hardware (from performance.psm1)
    $HWProfile = Get-HardwareProfile

    Write-Section "Starting Preset 1: Safe / Main"

    # These functions come from debloat.psm1
    Create-RestorePointSafe
    Clear-TempFiles

    # Privacy (privacy.psm1) and Debloat
    Apply-PrivacyTelemetrySafe
    $debloatResult = Apply-DebloatSafe
    $Status.PackagesFailed += $debloatResult.Failed

    # Preferences (privacy.psm1) and Extras
    Apply-PreferencesSafe
    Invoke-SafeOptionalPrompts

    # Performance (performance.psm1)
    Handle-SysMainPrompt -HardwareProfile $HWProfile
    Apply-PerformanceBaseline -HardwareProfile $HWProfile
    Ensure-PowerPlan -Mode 'HighPerformance'

    $Status.RebootRequired = $true

    # Summary (ui.psm1)
    Write-OutcomeSummary -Status $Status
    Write-Host "[+] Safe / Main preset applied. Restart when possible." -ForegroundColor Green
}

function Run-PCSlowPreset {
    $Status = @{ PackagesFailed = @(); RebootRequired = $false }
    $HWProfile = Get-HardwareProfile
    $OemServices = Get-OEMServiceInfo

    Write-Section "Starting Preset 2: Slow PC / Aggressive"

    Create-RestorePointSafe
    Clear-TempFiles

    # Safe baseline
    Apply-PrivacyTelemetrySafe
    $debloatResult = Apply-DebloatSafe
    $Status.PackagesFailed += $debloatResult.Failed
    Apply-PreferencesSafe

    # Performance Aggressive
    Apply-PerformanceBaseline -HardwareProfile $HWProfile
    Ensure-PowerPlan -Mode 'HighPerformance'

    # Aggressive tweaks (aggressive.psm1)
    Apply-AggressiveTweaks -HardwareProfile $HWProfile -FailedPackages ([ref]$Status.PackagesFailed) -OemServices $OemServices

    $Status.RebootRequired = $true

    Write-OutcomeSummary -Status $Status
    Write-Host "[+] Slow PC / Aggressive preset applied. Please restart." -ForegroundColor Green
}

# ---------- 5. MAIN LOOP (MENU) ----------

do {
    Show-Banner
    Write-Host "1) Apply Preset Safe / Main"
    Write-Host "2) Apply Preset Slow PC / Aggressive"
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
