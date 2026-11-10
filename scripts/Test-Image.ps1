[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root
$Compose = @('compose','-f','compose.yaml')
if (Test-Path -LiteralPath '.env.ai') { $Compose += @('-f','compose.ai.yaml') }
$Compose += @('-f','compose.runtime.yaml')
$Ids = @(& docker @Compose ps -q clipforge | Where-Object { $_ -match '^[a-f0-9]{12,64}$' })
if ($LASTEXITCODE -ne 0 -or $Ids.Count -ne 1) { throw 'Inicia la imagen preparada antes de comprobarla.' }
$Image = (& docker inspect --format '{{.Image}}' $Ids[0]).Trim()
if ($LASTEXITCODE -ne 0 -or $Image -notmatch '^sha256:[a-f0-9]{64}$') { throw 'No se pudo identificar la imagen.' }
$Tag = 'clipforge/test-base:' + $Image.Substring(7)
$TestTag = 'clipforge/tests:0.4.2-' + $Image.Substring(7,12)
& docker image tag $Image $Tag
if ($LASTEXITCODE -ne 0) { throw 'No se pudo conservar la imagen de prueba.' }
# Only the disposable TEST image downloads test-client libraries. No real AI key/data passed.
& docker build -f Dockerfile.tests --build-arg "RUNTIME_IMAGE=$Tag" -t $TestTag .
if ($LASTEXITCODE -ne 0) { throw 'No se pudo construir la imagen de pruebas; produccion intacta.' }
$Evidence = Join-Path $Root 'evidence'
New-Item -ItemType Directory -Path $Evidence -Force | Out-Null
$Log = Join-Path $Evidence ('unit-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.log')
# No user volumes, no credentials, no external network; localhost stubs only.
$SavedPreference = $ErrorActionPreference
try {
    # Windows PowerShell 5.1 maps native stderr to ErrorRecord when redirected.
    # unittest intentionally writes progress there; judge the exit code, not stderr.
    $ErrorActionPreference = 'Continue'
    & docker run --rm --network none --env CLIPFORGE_DATA_DIR=/tmp/clipforge-tests --env CLIPFORGE_AI_PROVIDER=disabled $TestTag 2>&1 | Tee-Object -FilePath $Log
    $Result = $LASTEXITCODE
} finally {
    $ErrorActionPreference = $SavedPreference
}
if ($Result -ne 0) { throw "Regresiones fallidas. Evidencia: $Log" }
Write-Host "Regresiones aprobadas. Imagen de produccion sin cambios: $Image"
