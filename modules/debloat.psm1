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

    $failed = @()
    foreach ($a in $apps) {
        $pkg = Get-AppxPackage -AllUsers -Name $a -ErrorAction SilentlyContinue
        if ($pkg) {
            Write-Host "  [+] Quitando $a"
            try {
                Get-AppxPackage -AllUsers -Name $a | Remove-AppxPackage -ErrorAction SilentlyContinue
            } catch {
                $failed += $a
                Write-Host "    [-] Error quitando $a : $_" -ForegroundColor Yellow
            }
        } else {
            Write-Host "  [ ] $a no está instalado."
        }
    }

    [pscustomobject]@{
        Failed = $failed
    }
}

Export-ModuleMember -Function Create-RestorePointSafe, Clear-TempFiles, Clear-DeepTempAndThumbs, Apply-DebloatSafe
