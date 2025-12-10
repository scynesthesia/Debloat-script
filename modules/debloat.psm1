function Create-RestorePointSafe {
    Write-Section "Creating restore point"
    try {
        Checkpoint-Computer -Description "Scynesthesia Optimizer v0.1" -RestorePointType "MODIFY_SETTINGS"
        Write-Host "  [+] Restore point created."
    } catch {
        Write-Host "  [!] Unable to create restore point (is system protection disabled?)" -ForegroundColor Yellow
    }
}

function Clear-TempFiles {
    Write-Section "Clearing basic temporary files"
    $paths = @(
        "$env:TEMP",
        "$env:WINDIR\Temp"
    )

    foreach ($p in $paths) {
        if (Test-Path $p) {
            Write-Host "  [+] Cleaning $p"
            try {
                Get-ChildItem $p -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
            } catch {
                Write-Host "    [-] Error cleaning $p : $_" -ForegroundColor Yellow
            }
        }
    }

    $wu = "$env:WINDIR\SoftwareDistribution\Download"
    if (Test-Path $wu) {
        Write-Host "  [+] Cleaning Windows Update cache"
        try {
            Get-ChildItem $wu -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
        } catch {
            Write-Host "    [-] Error cleaning SoftwareDistribution : $_" -ForegroundColor Yellow
        }
    }
}

function Clear-DeepTempAndThumbs {
    Write-Section "Extra cleanup (temp + thumbnails)"
    Clear-TempFiles

    $thumbDir = "$env:LOCALAPPDATA\Microsoft\Windows\Explorer"
    if (Test-Path $thumbDir) {
        Write-Host "  [+] Removing thumbnail cache"
        try {
            Get-ChildItem $thumbDir -Filter "thumbcache_*" -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
        } catch {
            Write-Host "    [-] Could not clear thumbnails: $_" -ForegroundColor Yellow
        }
    }
}

function Apply-DebloatSafe {
    param(
        [string[]] $AppList = @(
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
    )

    Write-Section "Safe debloat (removes common bloatware, keeps Store and essentials)"

    $failed = @()
    foreach ($a in $AppList) {
        $pkg = Get-AppxPackage -AllUsers -Name $a -ErrorAction SilentlyContinue
        if ($pkg) {
            Write-Host "  [+] Removing $a"
            try {
                Get-AppxPackage -AllUsers -Name $a | Remove-AppxPackage -ErrorAction SilentlyContinue
            } catch {
                $failed += $a
                Write-Host "    [-] Error removing $a : $_" -ForegroundColor Yellow
            }
        } else {
            Write-Host "  [ ] $a is not installed."
        }
    }

    [pscustomobject]@{
        Failed = $failed
    }
}

function Apply-DebloatAggressive {
    param(
        [string[]] $AppList = @(
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
    )

    Write-Section "Aggressive debloat (includes optional removal of provisioned packages)"

    $failed = @()
    foreach ($a in $AppList) {
        $pkg = Get-AppxPackage -AllUsers -Name $a -ErrorAction SilentlyContinue
        if ($pkg) {
            Write-Host "  [+] Removing $a"
            try {
                Get-AppxPackage -AllUsers -Name $a | Remove-AppxPackage -ErrorAction SilentlyContinue
            } catch {
                $failed += $a
                Write-Host "    [-] Error removing $a : $_" -ForegroundColor Yellow
            }
        } else {
            Write-Host "  [ ] $a is not installed."
        }
    }

    if (Ask-YesNo -Question "Also remove provisioned packages for future users? (More aggressive) [y/N]" -Default 'n') {
        $prov = Get-AppxProvisionedPackage -Online | Where-Object { $AppList -contains $_.PackageName }
        foreach ($p in $prov) {
            Write-Host "  [+] Removing provisioned package $($p.PackageName)"
            try {
                Remove-AppxProvisionedPackage -Online -PackageName $p.PackageName | Out-Null
            } catch {
                $failed += $p.PackageName
                Write-Host "    [-] Error removing provisioned package $($p.PackageName) : $_" -ForegroundColor Yellow
            }
        }
    }

    [pscustomobject]@{
        Failed = $failed
    }
}

Export-ModuleMember -Function Create-RestorePointSafe, Clear-TempFiles, Clear-DeepTempAndThumbs, Apply-DebloatSafe, Apply-DebloatAggressive
