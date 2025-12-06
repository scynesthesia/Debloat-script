# Nahue Windows Optimizer v0.1
# Presets:
#   1) SOC / Main (seguro)
#   2) PC lenta / agresivo (incluye el 1 + tweaks extra)
# Ejecutar SIEMPRE como Administrador.

$ScriptPath = $PSScriptRoot
Import-Module "$ScriptPath\modules\ui.psm1" -Force
Import-Module "$ScriptPath\modules\privacy.psm1" -Force
Import-Module "$ScriptPath\modules\debloat.psm1" -Force
Import-Module "$ScriptPath\modules\performance.psm1" -Force
Import-Module "$ScriptPath\modules\aggressive.psm1" -Force

# ---------- COMPROBACIÓN ADMIN ----------
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[!] Ejecutá este script como administrador." -ForegroundColor Red
    Read-Host "Presioná Enter para salir"
    exit 1
}
# ---------- CONTEXTO DE HARDWARE ----------
$hardwareProfile = Get-HardwareProfile
$oemServices = Get-OEMServiceInfo

Write-Section "Perfil detectado"
Write-Host "Equipo: " -NoNewline
if ($hardwareProfile.IsLaptop) {
    Write-Host "Laptop" -ForegroundColor Yellow
} else {
    Write-Host "Desktop" -ForegroundColor Green
}
Write-Host "RAM: $($hardwareProfile.TotalMemoryGB) GB ($($hardwareProfile.MemoryCategory))" -ForegroundColor Gray
Write-Host "Almacenamiento: " -NoNewline
if ($hardwareProfile.HasSSD -and $hardwareProfile.HasHDD) {
    Write-Host "SSD + HDD mixto" -ForegroundColor Gray
} elseif ($hardwareProfile.HasSSD) {
    Write-Host "SSD" -ForegroundColor Green
} else {
    Write-Host "HDD" -ForegroundColor Yellow
}
if ($oemServices -and $oemServices.Count -gt 0) {
    Write-Host "Servicios OEM detectados: $($oemServices.DisplayName -join ', ')" -ForegroundColor Yellow
}

# ---------- STATUS TRACKING ----------
$status = @{ PackagesFailed = @(); RebootRequired = $false }

function Ensure-PowerPlan {
    param(
        [ValidateSet('Balanced','HighPerformance')][string]$Mode = 'HighPerformance'
    )
    if ($Mode -eq 'HighPerformance') {
        powercfg /setactive SCHEME_MIN
    } else {
        powercfg /setactive SCHEME_BALANCED
    }
}

function Apply-SOCProfile {
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

    $StatusRef.Value.RebootRequired = $true
    Write-Host ""
    Write-Host "[+] Preset SOC / Main aplicado. Reiniciá el sistema cuando puedas." -ForegroundColor Green
    Write-OutcomeSummary -Status $StatusRef.Value
}

function Run-PCSlowPreset {
    param(
        $HardwareProfile,
        [ref]$StatusRef,
        $OemServices
    )

    Write-Section "Preset 2: PC Lenta / Agresivo"
    Create-RestorePointSafe
    Clear-TempFiles
    Apply-PrivacyTelemetrySafe
    Apply-PrivacyHardeningExtra
    $debloat = Apply-DebloatSafe
    $StatusRef.Value.PackagesFailed += $debloat.Failed
    Apply-PreferencesSafe
    Apply-PerformanceBaseline -HardwareProfile $HardwareProfile
    Apply-AggressiveTweaks -HardwareProfile $HardwareProfile -FailedPackages ([ref]$StatusRef.Value.PackagesFailed) -OemServices $OemServices

    $StatusRef.Value.RebootRequired = $true
    Write-Host ""
    Write-Host "[+] Preset PC Lenta / Agresivo aplicado. Reiniciá el sistema." -ForegroundColor Green
    Write-OutcomeSummary -Status $StatusRef.Value
}

# ---------- MENÚ PRINCIPAL ----------

do {
    Write-Host "===== Nahue Optimizer v0.1 =====" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "1) Aplicar Preset SOC / Main (seguro)"
    Write-Host "2) Aplicar Preset PC Lenta / Agresivo"
    Write-Host "0) Salir"
    Write-Host ""
    $choice = Read-MenuChoice "Elegí una opción" @('1','2','0')

    switch ($choice) {
        '1' { Apply-SOCProfile -HardwareProfile $hardwareProfile -StatusRef ([ref]$status) }
        '2' { Run-PCSlowPreset -HardwareProfile $hardwareProfile -StatusRef ([ref]$status) -OemServices $oemServices }
        '0' { break }
    }

    if ($choice -ne '0') {
        Write-Host ""
        Read-Host "Presioná Enter para volver al menú"
        Clear-Host
        Write-Section "Perfil detectado"
        Write-Host "Equipo: " -NoNewline
        if ($hardwareProfile.IsLaptop) {
            Write-Host "Laptop" -ForegroundColor Yellow
        } else {
            Write-Host "Desktop" -ForegroundColor Green
        }
        Write-Host "RAM: $($hardwareProfile.TotalMemoryGB) GB ($($hardwareProfile.MemoryCategory))" -ForegroundColor Gray
        Write-Host "Almacenamiento: " -NoNewline
        if ($hardwareProfile.HasSSD -and $hardwareProfile.HasHDD) {
            Write-Host "SSD + HDD mixto" -ForegroundColor Gray
        } elseif ($hardwareProfile.HasSSD) {
            Write-Host "SSD" -ForegroundColor Green
        } else {
            Write-Host "HDD" -ForegroundColor Yellow
        }
        if ($oemServices -and $oemServices.Count -gt 0) {
            Write-Host "Servicios OEM detectados: $($oemServices.DisplayName -join ', ')" -ForegroundColor Yellow
        }
    }
} while ($true)
