function Invoke-NetworkSoftReset {
    Write-Section "Reparación Básica de Red"

    Write-Host "Se limpiará DNS y se renovará la IP. Esto NO toca el firewall ni configuraciones avanzadas." -ForegroundColor Gray

    if (Ask-YesNo "¿Querés ejecutar la reparación básica de red?" 'n') {
        ipconfig /flushdns | Out-Null
        ipconfig /release | Out-Null
        ipconfig /renew | Out-Null
        Write-Host "[OK] Reparación básica de red finalizada." -ForegroundColor Green

        if (Ask-YesNo "¿También querés ejecutar 'netsh winsock reset'? (Requiere reinicio)" 'n') {
            netsh winsock reset | Out-Null
            Write-Host "[OK] Winsock reseteado. Reiniciar para aplicar cambios." -ForegroundColor Yellow
        }
    }
}

function Invoke-SystemRepair {
    Write-Section "Verificación de Integridad de Windows (SFC)"
    Write-Host "Esto busca archivos corruptos del sistema y los repara automáticamente." -ForegroundColor Gray

    if (Ask-YesNo "¿Iniciar SFC /scannow?" 'n') {
        sfc /scannow
        Write-Host "[OK] SFC finalizado." -ForegroundColor Green
    }
}

Export-ModuleMember -Function Invoke-NetworkSoftReset, Invoke-SystemRepair
