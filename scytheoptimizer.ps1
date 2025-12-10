# Deprecated entrypoint. Redirecting to scynesthesiaoptimizer.ps1
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$newPath = Join-Path $scriptDir 'scynesthesiaoptimizer.ps1'
. $newPath
