function Write-Section {
    param([string]$Text)
    Write-Host ""
    Write-Host "========== $Text ==========" -ForegroundColor Cyan
}

function Ask-YesNo {
    param(
        [string]$Question,
        [string]$Default = 'n'
    )

    $defaultText = if ($Default -match '^[yY]$') { '[Y/n]' } else { '[y/N]' }
    while ($true) {
        $resp = Read-Host "$Question $defaultText"
        if ([string]::IsNullOrWhiteSpace($resp)) { $resp = $Default }

        switch ($resp.ToLower()) {
            { $_ -in 'y' } { return $true }
            { $_ -in 'n' } { return $false }
            default { Write-Host "  [!] Invalid option. Please answer y/n." -ForegroundColor Yellow }
        }
    }
}

function Read-MenuChoice {
    param(
        [string]$Prompt,
        [string[]]$ValidOptions
    )

    while ($true) {
        $choice = Read-Host $Prompt
        if ($ValidOptions -contains $choice) { return $choice }
        Write-Host "[!] Invalid option" -ForegroundColor Yellow
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
        Write-Host "  [-] Error at $Path -> $Name : $_" -ForegroundColor Red
    }
}

function Write-OutcomeSummary {
    param(
        [hashtable]$Status
    )

    Write-Host ""
    Write-Host "===== Summary =====" -ForegroundColor Cyan
    Write-Host "[+] Privacy hardened" -ForegroundColor Green
    Write-Host "[+] Debloat applied" -ForegroundColor Green
    Write-Host "[+] Performance tweaks applied" -ForegroundColor Green

    if ($Status.PackagesFailed.Count -gt 0) {
        Write-Host "[X] Some packages could not be removed ($($Status.PackagesFailed -join ', '))" -ForegroundColor Yellow
    } else {
        Write-Host "[+] All targeted packages removed" -ForegroundColor Green
    }

    if ($Status.RebootRequired) {
        Write-Host "[!] Reboot required" -ForegroundColor Yellow
    } else {
        Write-Host "[ ] Reboot optional" -ForegroundColor Gray
    }
}

Export-ModuleMember -Function Write-Section, Ask-YesNo, Read-MenuChoice, Set-RegistryValueSafe, Write-OutcomeSummary
