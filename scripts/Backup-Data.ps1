[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root
$Compose = @('compose','-f','compose.yaml')
if (Test-Path -LiteralPath '.env.ai') { $Compose += @('-f','compose.ai.yaml') }
if (Test-Path -LiteralPath 'compose.runtime.yaml') { $Compose += @('-f','compose.runtime.yaml') }
$Ids = @(& docker @Compose ps -a -q clipforge | Where-Object { $_ -match '^[a-f0-9]{12,64}$' })
if ($LASTEXITCODE -ne 0 -or $Ids.Count -ne 1) { throw 'No se encontro exactamente un contenedor.' }
$Container = $Ids[0]
$Image = (& docker inspect --format '{{.Image}}' $Container).Trim()
if ($LASTEXITCODE -ne 0) { throw 'No se pudo leer la imagen.' }
$State = (& docker inspect --format '{{.State.Running}}' $Container).Trim()
if ($LASTEXITCODE -ne 0 -or $State -ne 'false') { throw 'Espera los trabajos y detiene el servicio primero con compose stop clipforge.' }
$BackupDir = Join-Path $Root 'backups'
New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null
$Name = 'clipforge-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.zip'
& docker run --rm --network none --entrypoint python --volumes-from $Container --mount "type=bind,source=$BackupDir,target=/backups" $Image -m app.backup create --data /data --output "/backups/$Name"
if ($LASTEXITCODE -ne 0) { throw 'Backup no completado. No se eliminaron los originales.' }
Write-Host "Backup verificado: backups/$Name. Es privado y NO esta cifrado. Copialo a un destino protegido."
