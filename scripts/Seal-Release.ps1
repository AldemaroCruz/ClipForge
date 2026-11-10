[CmdletBinding()]
param([switch]$SaveImage)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root
$Compose = @('compose','-f','compose.yaml')
if (Test-Path -LiteralPath '.env.ai') { $Compose += @('-f','compose.ai.yaml') }
$Compose += @('-f','compose.runtime.yaml')
$Ids = @(& docker @Compose ps -q clipforge | Where-Object { $_ -match '^[a-f0-9]{12,64}$' })
if ($LASTEXITCODE -ne 0 -or $Ids.Count -ne 1) { throw 'No hay una instancia preparada en ejecucion.' }
$Health = Invoke-RestMethod 'http://127.0.0.1:8080/health'
if ($Health.version -ne '0.4.2') { throw 'Version inesperada.' }
$Image = (& docker inspect --format '{{.Image}}' $Ids[0]).Trim()
if ($LASTEXITCODE -ne 0) { throw 'No se pudo leer la imagen.' }
& docker exec $Ids[0] python release-tools/verify_runtime.py release-tools/runtime-lock.json
if ($LASTEXITCODE -ne 0) { throw 'El runtime no coincide con su lock.' }
$Out = Join-Path $Root ('release/sealed-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
New-Item -ItemType Directory -Path $Out | Out-Null
@{schema=1;version='0.4.2';local_image_id=$Image;registry_digest=$null;sealed_at=(Get-Date).ToUniversalTime().ToString('o');
  acceptance='see evidence separately';approved_for_cloud=$false} | ConvertTo-Json | Set-Content (Join-Path $Out 'image.json') -Encoding UTF8
if ($SaveImage) {
    & docker image save --output (Join-Path $Out 'clipforge-0.4.2.tar') $Image
    if ($LASTEXITCODE -ne 0) { throw 'No se pudo guardar la imagen.' }
    $Hash = (Get-FileHash -Algorithm SHA256 (Join-Path $Out 'clipforge-0.4.2.tar')).Hash.ToLowerInvariant()
    "$Hash  clipforge-0.4.2.tar" | Set-Content (Join-Path $Out 'clipforge-0.4.2.tar.sha256') -Encoding ASCII
}
Write-Host "Imagen identificada en $Out. Es ID local, no digest de registry. No se desplego nada."
