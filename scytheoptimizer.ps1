<#
    ScytheOptimizer - Base script
    Presets:
      1. SOC / Main (safe)
      2. PC Lenta / Agresivo (adds extra non-destructive tweaks)
    Notes:
      - Avoids disabling Defender, SmartScreen, mitigations or critical security features.
      - Does not remove Edge, Microsoft Store or WebView2.
      - Organized functions for later modularization.
#>

# Requires elevation for most changes
function Ensure-Administrator {
    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Warning "Este script debe ejecutarse como Administrador."
        exit 1
    }
}

function Write-Section($Title) {
    Write-Host "`n==== $Title ====``n" -ForegroundColor Cyan
}

function Set-PolicyValue {
    param(
        [Parameter(Mandatory)] [string]$Path,
        [Parameter(Mandatory)] [string]$Name,
        [Parameter(Mandatory)] [object]$Value,
        [ValidateSet('DWord','QWord','String','ExpandString','Binary')] [string]$Type = 'DWord'
    )

    if (-not (Test-Path $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }
    Set-ItemProperty -Path $Path -Name $Name -Type $Type -Value $Value -Force
}

function Invoke-PrivacyTelemetrySafe {
    Write-Section "Privacidad y telemetría (seguro)"

    # Desactiva experiencias sugeridas y feedback frecuente
    Set-PolicyValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -Value 0
    Set-PolicyValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-310093Enabled" -Value 0
    Set-PolicyValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Value 0

    # Desactiva anuncios personalizados y diagnósticos más ligeros
    Set-PolicyValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Value 0
    Set-PolicyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 1
    Set-PolicyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Value 0
    Set-PolicyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Value 0
    Set-PolicyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -Value 0

    # No desactiva SmartScreen ni Defender
    Write-Host "Telemetría básica aplicada (sin tocar Defender/SmartScreen)."
}

function Invoke-DebloatSafe {
    Write-Section "Debloat seguro"

    $safeApps = @(
        "Microsoft.3DBuilder",
        "Microsoft.BingNews",
        "Microsoft.GetHelp",
        "Microsoft.Getstarted",
        "Microsoft.Microsoft3DViewer",
        "Microsoft.MicrosoftOfficeHub",
        "Microsoft.MicrosoftSolitaireCollection",
        "Microsoft.MicrosoftStickyNotes",
        "Microsoft.MixedReality.Portal",
        "Microsoft.People",
        "Microsoft.Print3D",
        "Microsoft.SkypeApp",
        "Microsoft.WindowsFeedbackHub",
        "Microsoft.ZuneMusic",
        "Microsoft.ZuneVideo"
    )

    foreach ($app in $safeApps) {
        Get-AppxPackage -Name $app -AllUsers | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
        Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -eq $app } | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
    }

    Write-Host "Aplicaciones consideradas seguras para remover han sido desinstaladas."
}

function Invoke-PreferencesSafe {
    Write-Section "Preferencias (seguro)"

    # Mostrar extensiones y archivos ocultos
    Set-PolicyValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Value 0
    Set-PolicyValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Value 1

    # Desactivar notificaciones molestas
    Set-PolicyValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "ToastEnabled" -Value 0

    # Ajustes visuales: mejor rendimiento manteniendo efectos básicos
    Set-PolicyValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name "VisualFXSetting" -Value 2

    Write-Host "Preferencias aplicadas sin cambios críticos."
}

function Invoke-AggressiveTweaks {
    Write-Section "Tweaks adicionales (PC lenta / agresivo)"

    # Limitar aplicaciones en segundo plano (sin tocar apps críticas)
    Set-PolicyValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" -Name "GlobalUserDisabled" -Value 1

    # Desactivar servicios de experiencias conectadas
    Set-PolicyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableCdp" -Value 0

    # Ajustar planificador de energía para mejores tiempos de respuesta
    powercfg /setacvalueindex SCHEME_MIN SUB_PROCESSOR PROCTHROTTLEMIN 100 | Out-Null
    powercfg /setacvalueindex SCHEME_MIN SUB_PROCESSOR PROCTHROTTLEMAX 100 | Out-Null
    powercfg /setactive SCHEME_MIN | Out-Null

    Write-Host "Tweaks agresivos aplicados (sin desactivar características de seguridad)."
}

function Set-PowerPlan {
    param(
        [ValidateSet('Balanced','HighPerformance')][string]$Mode = 'Balanced'
    )

    Write-Section "Plan de energía"

    $guid = switch ($Mode) {
        'HighPerformance' { '8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c' }
        Default { '381b4222-f694-41f0-9685-ff5bb260df2e' }
    }

    powercfg /setactive $guid | Out-Null
    Write-Host "Plan de energía establecido en $Mode."
}

function Apply-SOCProfile {
    Write-Section "Aplicando preset SOC / Main"
    Invoke-PrivacyTelemetrySafe
    Invoke-DebloatSafe
    Invoke-PreferencesSafe
    Set-PowerPlan -Mode 'Balanced'
    Write-Host "Preset SOC / Main completado."
}

function Apply-AggressiveProfile {
    Write-Section "Aplicando preset PC Lenta / Agresivo"
    Invoke-PrivacyTelemetrySafe
    Invoke-DebloatSafe
    Invoke-PreferencesSafe
    Invoke-AggressiveTweaks
    Set-PowerPlan -Mode 'HighPerformance'
    Write-Host "Preset PC Lenta / Agresivo completado."
}

function Show-Menu {
    Clear-Host
    Write-Host "ScytheOptimizer - versión base" -ForegroundColor Green
    Write-Host "1. Preset SOC / Main (seguro)"
    Write-Host "2. Preset PC Lenta / Agresivo"
    Write-Host "0. Salir"
    Write-Host
}

Ensure-Administrator

$exit = $false
while (-not $exit) {
    Show-Menu
    $choice = Read-Host "Selecciona una opción"
    switch ($choice) {
        '1' { Apply-SOCProfile; Pause }
        '2' { Apply-AggressiveProfile; Pause }
        '0' { $exit = $true }
        Default { Write-Host "Opción no válida" -ForegroundColor Yellow; Start-Sleep -Seconds 1 }
    }
}

Write-Host "Gracias por usar ScytheOptimizer."
