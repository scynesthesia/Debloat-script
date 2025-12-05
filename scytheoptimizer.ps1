<#
    ScytheOptimizer - versión base mejorada
    Presets:
      1. SOC / Main (seguro)
      2. PC Lenta / Agresivo (añade extras no destructivos)
    Notas:
      - No desactiva Defender, SmartScreen, mitigaciones ni borra Edge/Store/WebView2.
      - Plan de energía predeterminado: Alto rendimiento en todos los presets.
      - Código modular y comentado para futura expansión.
#>

function Ensure-Administrator {
    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Warning "Este script debe ejecutarse como Administrador."
        exit 1
    }
}

function Write-Section {
    param([string]$Title)
    Write-Host "`n====================" -ForegroundColor Cyan
    Write-Host " $Title" -ForegroundColor Cyan
    Write-Host "====================`n" -ForegroundColor Cyan
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

    # Desactiva experiencias sugeridas y recomendaciones
    Set-PolicyValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -Value 0
    Set-PolicyValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-310093Enabled" -Value 0
    Set-PolicyValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Value 0
    Set-PolicyValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SoftLandingEnabled" -Value 0

    # Anuncios personalizados y diagnósticos básicos
    Set-PolicyValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Value 0
    Set-PolicyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 1
    Set-PolicyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Value 0
    Set-PolicyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Value 0
    Set-PolicyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -Value 0

    # Limitar búsquedas en la nube desde Inicio sin desactivar seguridad
    Set-PolicyValue -Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer" -Name "DisableSearchBoxSuggestions" -Value 1

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

    # Tema oscuro y atenuación de efectos visuales
    Set-PolicyValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -Value 0
    Set-PolicyValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "SystemUsesLightTheme" -Value 0
    Set-PolicyValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name "VisualFXSetting" -Value 2

    # Explorador: extensiones y archivos ocultos
    Set-PolicyValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Value 0
    Set-PolicyValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Value 1

    # Notificaciones y contenido recomendado
    Set-PolicyValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "ToastEnabled" -Value 0
    Set-PolicyValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_IrisRecommendations" -Value 0
    Set-PolicyValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement" -Name "ScoobeSystemSettingEnabled" -Value 0

    Write-Host "Preferencias aplicadas sin cambios críticos."
}

function Invoke-AggressiveTweaks {
    Write-Section "Tweaks adicionales (PC lenta / agresivo)"

    # Limitar aplicaciones en segundo plano (sin tocar apps críticas)
    Set-PolicyValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" -Name "GlobalUserDisabled" -Value 1

    # Desactivar GameDVR y grabación en segundo plano
    Set-PolicyValue -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_Enabled" -Value 0
    Set-PolicyValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Name "AppCaptureEnabled" -Value 0

    # Reducir servicios de experiencias conectadas
    Set-PolicyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableCdp" -Value 0

    Write-Host "Tweaks agresivos aplicados (sin desactivar características de seguridad)."
}

function Ensure-PowerPlan {
    param(
        [ValidateSet('Balanced','HighPerformance','Ultimate')][string]$Mode = 'HighPerformance'
    )

    Write-Section "Plan de energía"

    switch ($Mode) {
        'Ultimate' {
            # Crea el plan Ultimate Performance si no existe
            $ultimate = (powercfg -L) -match 'Ultimate Performance'
            if (-not $ultimate) {
                powercfg -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61 | Out-Null
            }
            $guid = (powercfg -L) | Where-Object { $_ -match 'Ultimate Performance' } | ForEach-Object { ($_ -split '\s+')[3] }
        }
        'HighPerformance' {
            $guid = '8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c'
        }
        Default {
            $guid = '381b4222-f694-41f0-9685-ff5bb260df2e'
        }
    }

    if ($guid) {
        powercfg /setactive $guid | Out-Null
        Write-Host "Plan de energía establecido en $Mode."
    } else {
        Write-Warning "No se pudo establecer el plan de energía: GUID no encontrado."
    }
}

function Apply-SOCProfile {
    Write-Section "Aplicando preset SOC / Main"
    Invoke-PrivacyTelemetrySafe
    Invoke-DebloatSafe
    Invoke-PreferencesSafe
    Ensure-PowerPlan -Mode 'HighPerformance'
    Write-Host "Preset SOC / Main completado."
}

function Apply-AggressiveProfile {
    Write-Section "Aplicando preset PC Lenta / Agresivo"
    Invoke-PrivacyTelemetrySafe
    Invoke-DebloatSafe
    Invoke-PreferencesSafe
    Invoke-AggressiveTweaks
    Ensure-PowerPlan -Mode 'Ultimate'
    Write-Host "Preset PC Lenta / Agresivo completado."
}

function Show-Menu {
    Show-Banner
    Write-Host "[1] Preset SOC / Main (seguro)" -ForegroundColor White
    Write-Host "[2] Preset PC Lenta / Agresivo" -ForegroundColor White
    Write-Host "[0] Salir" -ForegroundColor White
    Write-Host
}

Ensure-Administrator
Ensure-PowerPlan -Mode 'HighPerformance'  # Base siempre en alto rendimiento

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

Write-Host "Gracias por usar ScytheOptimizer." -ForegroundColor Green
