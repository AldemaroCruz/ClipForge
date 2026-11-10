[CmdletBinding()]
param([Parameter(Mandatory=$true)][ValidatePattern('^[a-f0-9]{32}$')][string]$ProjectId,
      [switch]$ContentReviewed,[switch]$Manual)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root
$Compose = @('compose','-f','compose.yaml')
if (Test-Path -LiteralPath '.env.ai') { $Compose += @('-f','compose.ai.yaml') }
if (Test-Path -LiteralPath 'compose.runtime.yaml') { $Compose += @('-f','compose.runtime.yaml') }
$Ids = @(& docker @Compose ps -a -q clipforge | Where-Object { $_ -match '^[a-f0-9]{12,64}$' })
if ($LASTEXITCODE -ne 0 -or $Ids.Count -ne 1) { throw 'No se encontro el contenedor.' }
$Image = (& docker inspect --format '{{.Image}}' $Ids[0]).Trim()
if ($LASTEXITCODE -ne 0) { throw 'No se pudo leer la imagen.' }
$Evidence = Join-Path $Root 'evidence'
New-Item -ItemType Directory -Path $Evidence -Force | Out-Null
$Name = $ProjectId.Substring(0,8) + '-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.json'
$Arguments = @('run','--rm','--network','none','--entrypoint','python','--volumes-from',"$($Ids[0]):ro",
    '--mount',"type=bind,source=$Evidence,target=/evidence",$Image,'-m','app.acceptance',
    '--data','/data','--project',$ProjectId,'--decode','--output',"/evidence/$Name")
if ($ContentReviewed) { $Arguments += '--reviewed-content' }
if ($Manual) { $Arguments += '--manual' }
& docker @Arguments
$Exit = $LASTEXITCODE
if ($Exit -eq 2) { Write-Warning "Aceptacion incompleta. Revisa evidence/$Name; no se llamo a IA." }
elseif ($Exit -ne 0) { throw 'Fallo verificando artefactos. No se envio material a un proveedor.' }
else { Write-Host "Evidencia: evidence/$Name. La revision editorial es una declaracion del operador." }
