# Upgrade from the RUNNING, trusted v0.4.1 image without resolving dependencies.
[CmdletBinding()]
param([switch]$SaveBaseImage, [switch]$CheckOnly)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root
function Docker-Checked {
    param([string[]]$Arguments)
    $result = & docker @Arguments
    if ($LASTEXITCODE -ne 0) { throw "Docker fallo: $($Arguments[0]). Revisa el error anterior." }
    return $result
}
$Compose = @('compose','-f','compose.yaml')
$WithAI = Test-Path -LiteralPath '.env.ai'
if ($WithAI) { $Compose += @('-f','compose.ai.yaml') }
$ids = @(Docker-Checked ($Compose + @('ps','-q','clipforge')) | Where-Object { $_ -match '^[a-f0-9]{12,64}$' })
if ($ids.Count -ne 1) { throw 'Se necesita un contenedor actual en ejecucion. NO ejecutes down ni reconstruyas primero.' }
$Container = $ids[0]
$Health = Invoke-RestMethod 'http://127.0.0.1:8080/health'
if ($Health.version -notin @('0.4.1','0.4.2')) { throw 'Ruta prevista: v0.4.1 o v0.4.2 ya instalada.' }
$BaseId = ((Docker-Checked @('inspect','--format','{{.Image}}',$Container)) -join '').Trim()
if ($BaseId -notmatch '^sha256:[0-9a-f]{64}$') { throw 'No se obtuvo un ID inmutable de la imagen.' }
# Explicit environment allowlist. Never dump Config.Env / compose config with secrets.
Docker-Checked @('cp','scripts/runtime_environment.py',"${Container}:/tmp/clipforge-runtime-env.py") | Out-Host
$ConfigJson = (Docker-Checked @('exec',$Container,'python','/tmp/clipforge-runtime-env.py')) -join "`n"
Docker-Checked @('exec',$Container,'rm','-f','/tmp/clipforge-runtime-env.py') | Out-Host
$Config = $ConfigJson | ConvertFrom-Json
$Model = [string]$Config.WHISPER_MODEL
if ([string]::IsNullOrEmpty($Model)) { $Model = 'tiny' }
if ($Model -notmatch '^[A-Za-z0-9._-]+$') { throw 'Modelo personalizado: captura manual requerida.' }
if ($Config.CLIPFORGE_DATA_DIR -and $Config.CLIPFORGE_DATA_DIR -ne '/data') { throw 'Esta ruta requiere el montaje estandar /data.' }
$HuggingFaceHome = [string]$Config.HF_HOME
if ([string]::IsNullOrEmpty($HuggingFaceHome)) { $HuggingFaceHome = '/models/huggingface' }
if ($HuggingFaceHome -ne '/models/huggingface') { throw 'Esta ruta requiere la cache estandar /models/huggingface.' }
if ($Root.Contains(',')) { throw 'Docker --mount no admite esta ruta con comas.' }
$Stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$ShortId = $BaseId.Substring(7,12)
$BaseTag = "clipforge/runtime-base:$($BaseId.Substring(7))"
$RelDir = "release/$Stamp-$ShortId"
$ReleaseDir = Join-Path $Root $RelDir
$BackupDir = Join-Path $Root 'backups'
$BackupName = "clipforge-before-042-$Stamp.zip"
# A direct Python script starts with /tools/scripts on sys.path, not /tools.
# Scope the import root to these helper containers only; do not change Windows
# environment variables, the running app, or the inherited production image.
$Tools = @('--mount',"type=bind,source=$Root\app,target=/tools/app,readonly",
           '--mount',"type=bind,source=$Root\scripts,target=/tools/scripts,readonly",
           '-w','/tools','--env','PYTHONPATH=/tools',
           '--env','PYTHONDONTWRITEBYTECODE=1')
$Offline = @('run','--rm','--network','none','--entrypoint','python','--volumes-from',"${Container}:ro")
# Before stop: verify mounted imports and active persisted work, without changing data.
Docker-Checked ($Offline + $Tools + @($BaseId,'scripts/check_idle.py')) | Out-Host
if ($CheckOnly) {
    Write-Host 'Preflight OK: imports del proyecto y estados persistidos comprobados.'
    Write-Host 'No se detuvo el servicio ni se crearon release/backup. No se llamo a IA.'
    Write-Host 'Esta comprobacion no valida todavia captura de modelo, backup ni build.'
    return
}
New-Item -ItemType Directory -Path $ReleaseDir -ErrorAction Stop | Out-Null
New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null
Write-Host 'Deteniendo el contenedor. No inicies trabajos durante la preparacion.'
Docker-Checked ($Compose + @('stop','clipforge')) | Out-Host
try {
    Docker-Checked @('image','tag',$BaseId,$BaseTag) | Out-Host
    Docker-Checked ($Offline + $Tools + @('--mount',"type=bind,source=$ReleaseDir,target=/capture",$BaseId,
        'scripts/capture_runtime.py','--output','/capture','--cache',$HuggingFaceHome,'--model',$Model)) | Out-Host
    # New backup code runs from tools. Original container is stopped; no external network.
    Docker-Checked (@('run','--rm','--network','none','--entrypoint','python','--volumes-from',$Container) + $Tools +
        @('--mount',"type=bind,source=$BackupDir,target=/backups",$BaseId,'-m','app.backup','create',
          '--data','/data','--output',"/backups/$BackupName")) | Out-Host
    if (Test-Path -LiteralPath 'compose.runtime.yaml') {
        Copy-Item 'compose.runtime.yaml' (Join-Path $ReleaseDir 'previous-compose.runtime.yaml')
    }
    $Overlay = @"
# Generated from the actual working image; do not hand-edit BASE_RUNTIME.
services:
  clipforge:
    image: clipforge/mvp:0.4.2-$Stamp
    build:
      context: .
      dockerfile: Dockerfile.runtime
      network: none
      args:
        BASE_RUNTIME: "$BaseTag"
        LOCK_DIR: "$RelDir"
    volumes:
      - "./${RelDir}:/release:ro"
    environment:
      WHISPER_MODEL: "$Model"
      CLIPFORGE_MODEL_LOCK: /release/model-lock.json
"@
    [IO.File]::WriteAllText((Join-Path $Root 'compose.runtime.yaml'),$Overlay,(New-Object Text.UTF8Encoding($false)))
    $Meta = @{ schema=1; previous_image_id=$BaseId; previous_tag=$BaseTag; previous_version=$Health.version;
        release_dir=$RelDir; backup=("backups/"+$BackupName); ai_overlay=$WithAI; prepared_at=(Get-Date).ToUniversalTime().ToString('o');
        status='prepared_not_built_or_accepted'; registry_digest=$null }
    $Meta | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $ReleaseDir 'upgrade.json') -Encoding UTF8
    $Meta | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $Root 'release/current.json') -Encoding UTF8
    if ($SaveBaseImage) {
        Docker-Checked @('image','save','--output',(Join-Path $ReleaseDir 'runtime-base.tar'),$BaseTag) | Out-Host
        Get-FileHash -Algorithm SHA256 (Join-Path $ReleaseDir 'runtime-base.tar') | Format-List
    }
    Write-Host "Preparacion completada. Backup: backups/$BackupName"
    Write-Host "Lock transitivo y revision del modelo: $RelDir"
    Write-Host 'Siguiente: .\scripts\Start-Release.ps1'
    Write-Host 'La imagen anterior esta conservada; el servicio sigue detenido hasta iniciar la nueva.'
} catch {
    Write-Host 'Preparacion incompleta. No se borraron tus datos ni la imagen anterior.'
    Write-Host 'Para volver al contenedor anterior: docker compose -f compose.yaml -f compose.ai.yaml start clipforge'
    throw
}
