function Apply-PrivacyTelemetrySafe {
    Write-Section "Aplicando tweaks de privacidad / telemetría (preset SOC seguro)"

    Set-RegistryValueSafe "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableConsumerFeatures" 1
    Set-RegistryValueSafe "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "AllowTelemetry" 0

    $sysPol = "HKLM\SOFTWARE\Policies\Microsoft\Windows\System"
    Set-RegistryValueSafe $sysPol "EnableActivityFeed" 0
    Set-RegistryValueSafe $sysPol "PublishUserActivities" 0
    Set-RegistryValueSafe $sysPol "UploadUserActivities" 0

    Set-RegistryValueSafe "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" "DisableLocation" 1
    Set-RegistryValueSafe "HKLM\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" "AutoConnectAllowedOEM" 0

    Set-RegistryValueSafe "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" "AllowGameDVR" 0
    Set-RegistryValueSafe "HKCU\System\GameConfigStore" "GameDVR_Enabled" 0
    Set-RegistryValueSafe "HKCU\System\GameConfigStore" "GameDVR_FSEBehaviorMode" 2

    if (Ask-YesNo "¿Desactivar Cortana y búsquedas online en Start?" 's') {
        Set-RegistryValueSafe "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" "BingSearchEnabled" 0
        Set-RegistryValueSafe "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" "CortanaConsent" 0
        Write-Host "  [+] Cortana y Bing en Start desactivados"
    } else {
        Write-Host "  [ ] Cortana/Bing se mantienen como están."
    }

    if (Ask-YesNo "¿Activar Storage Sense para limpieza automática básica?" 'n') {
        $storageSense = "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense"
        Set-RegistryValueSafe $storageSense "AllowStorageSenseGlobal" 1
        Set-RegistryValueSafe "$storageSense\Parameters\StoragePolicy" "01" 1
        Set-RegistryValueSafe "$storageSense\Parameters\StoragePolicy" "04" 1
        Write-Host "  [+] Storage Sense habilitado"
    } else {
        Write-Host "  [ ] Storage Sense sin cambios."
    }

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

    Set-RegistryValueSafe "HKLM\SOFTWARE\Microsoft\PowerShellCore\Telemetry" "EnableTelemetry" 0
}

function Apply-PreferencesSafe {
    Write-Section "Ajustando preferencias de UX (Start, Explorer, etc.)"

    Set-RegistryValueSafe "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "Hidden" 1
    Set-RegistryValueSafe "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "HideFileExt" 0

    Set-RegistryValueSafe "HKCU\Control Panel\Mouse" "MouseSpeed" 0
    Set-RegistryValueSafe "HKCU\Control Panel\Mouse" "MouseThreshold1" 0
    Set-RegistryValueSafe "HKCU\Control Panel\Mouse" "MouseThreshold2" 0

    Set-RegistryValueSafe "HKCU\Control Panel\Accessibility\StickyKeys" "Flags" 506

    Set-RegistryValueSafe "HKCU\SOFTWARE\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" "" "" ([Microsoft.Win32.RegistryValueKind]::String)

    Set-RegistryValueSafe "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "LaunchTo" 1

    Set-RegistryValueSafe "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl" "DisplayParameters" 1

    Set-RegistryValueSafe "HKCU\Control Panel\Keyboard" "InitialKeyboardIndicators" 2147483650
}

Export-ModuleMember -Function Apply-PrivacyTelemetrySafe, Apply-PreferencesSafe
