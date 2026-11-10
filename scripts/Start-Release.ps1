[CmdletBinding()]
param([switch]$NoBuild)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root
if (-not (Test-Path -LiteralPath 'compose.runtime.yaml')) { throw 'Ejecuta Prepare-Upgrade.ps1 primero.' }
$Meta = Get-Content -LiteralPath 'release/current.json' -Raw | ConvertFrom-Json
$BaseId = (& docker image inspect --format '{{.Id}}' $Meta.previous_tag).Trim()
if ($LASTEXITCODE -ne 0 -or $BaseId -ne $Meta.previous_image_id) { throw 'La etiqueta del runtime base ya no coincide con el ID capturado.' }
$Compose = @('compose','-f','compose.yaml')
if (Test-Path -LiteralPath '.env.ai') { $Compose += @('-f','compose.ai.yaml') }
$Compose += @('-f','compose.runtime.yaml')
if (-not $NoBuild) {
    & docker @Compose build clipforge
    if ($LASTEXITCODE -ne 0) { throw 'Build fallido. No se inicio una imagen diferente.' }
}
& docker @Compose up -d --no-build --pull never --wait --wait-timeout 120
if ($LASTEXITCODE -ne 0) { throw 'No se pudo iniciar la imagen preparada.' }
$Health = Invoke-RestMethod 'http://127.0.0.1:8080/health'
if ($Health.version -ne '0.4.2') { throw 'La version en ejecucion no es 0.4.2.' }
$Health | Format-List
Write-Host 'Abre http://127.0.0.1:8080/ops para metricas. No hubo consulta al proveedor de IA.'
