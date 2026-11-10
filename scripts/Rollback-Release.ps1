[CmdletBinding()]
param([switch]$ConfirmRollback)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root
if (-not $ConfirmRollback) { throw 'Revisa docs/OPERACION.md y usa -ConfirmRollback. Se cambia codigo, no se restaura data/.' }
$Meta = Get-Content -LiteralPath 'release/current.json' -Raw | ConvertFrom-Json
$BaseId = (& docker image inspect --format '{{.Id}}' $Meta.previous_tag).Trim()
if ($LASTEXITCODE -ne 0 -or $BaseId -ne $Meta.previous_image_id) { throw 'La imagen anterior no coincide o no esta disponible.' }
$Compose = @('compose','-f','compose.yaml')
if (Test-Path -LiteralPath '.env.ai') { $Compose += @('-f','compose.ai.yaml') }
$Current = $Compose + @('-f','compose.runtime.yaml')
$Summary = Invoke-RestMethod 'http://127.0.0.1:8080/ops/summary'
if (@($Summary.projects | Where-Object { $_.active_work -gt 0 }).Count -gt 0) { throw 'Hay trabajo en curso. Espera antes de cambiar de imagen.' }
& docker @Current stop clipforge
if ($LASTEXITCODE -ne 0) { throw 'No se pudo detener la version actual.' }
$Overlay = "services:`n  clipforge:`n    image: $($Meta.previous_tag)`n"
[IO.File]::WriteAllText((Join-Path $Root 'compose.rollback.yaml'),$Overlay,(New-Object Text.UTF8Encoding($false)))
# Deliberately OMIT compose.runtime.yaml, so the old app does not inherit new model-lock env.
$Rollback = $Compose + @('-f','compose.rollback.yaml')
& docker @Rollback up -d --no-build --pull never --wait --wait-timeout 120
if ($LASTEXITCODE -ne 0) { throw 'Rollback no completo; data/ no fue reemplazado.' }
Invoke-RestMethod 'http://127.0.0.1:8080/health' | Format-List
Write-Host 'Codigo anterior iniciado. Los datos nuevos se conservan: esto NO es rollback de esquema ni backup restore.'
