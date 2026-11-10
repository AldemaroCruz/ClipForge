# v0.4.2 restore hotfix 3. No application rebuild, no writes to the active data/.
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$Archive,
    [switch]$UseDockerVolume
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

function Get-DockerText {
    param([string[]]$Arguments)
    $Lines = @(& docker @Arguments)
    if ($LASTEXITCODE -ne 0) { throw ('Docker fallo: {0}. Revisa el error anterior.' -f $Arguments[0]) }
    return ($Lines -join "`n").Trim()
}

$File = (Resolve-Path -LiteralPath $Archive -ErrorAction Stop).Path
if (-not (Test-Path -LiteralPath $File -PathType Leaf)) { throw 'Archive debe ser un archivo ZIP.' }
$HashFile = $File + '.sha256'
if (-not (Test-Path -LiteralPath $HashFile -PathType Leaf)) { throw 'Falta el .sha256 externo. Conserva ambos archivos.' }
$Expected = ((Get-Content -LiteralPath $HashFile -Raw).Trim() -split '\s+')[0]
if ($Expected -notmatch '^[a-fA-F0-9]{64}$') { throw 'Hash invalido.' }
$Expected = $Expected.ToLowerInvariant()
$Verifier = Join-Path $PSScriptRoot 'verify_restore.py'
if (-not (Test-Path -LiteralPath $Verifier -PathType Leaf)) { throw 'Falta scripts/verify_restore.py. Copia ambos archivos del parche.' }
# Docker --mount is comma-separated; reject rather than misinterpret a source path.
foreach ($MountPath in @($File, $Verifier, $Root)) {
    if ($MountPath.Contains(',')) { throw 'Esta herramienta no admite comas en las rutas de montaje. Usa una ruta sin comas.' }
}

$Compose = @('compose','-f','compose.yaml')
if (Test-Path -LiteralPath '.env.ai') { $Compose += @('-f','compose.ai.yaml') }
if (Test-Path -LiteralPath 'compose.runtime.yaml') { $Compose += @('-f','compose.runtime.yaml') }
$IdText = Get-DockerText -Arguments ($Compose + @('ps','-a','-q','clipforge'))
$Ids = @($IdText -split '\r?\n' | Where-Object { $_ -match '^[a-f0-9]{12,64}$' })
if ($Ids.Count -ne 1) { throw 'No se encontro un unico contenedor instalado.' }
$Image = Get-DockerText -Arguments @('inspect','--format','{{.Image}}',$Ids[0])
if ($Image -notmatch '^sha256:[a-f0-9]{64}$') { throw 'No se pudo leer el ID de la imagen instalada.' }
$ImageOs = Get-DockerText -Arguments @('image','inspect','--format','{{.Os}}',$Image)
if ($ImageOs -ne 'linux') { throw 'Esta recuperacion requiere la imagen Linux instalada de ClipForge.' }

$RunId = (Get-Date -Format 'yyyyMMdd-HHmmss') + '-' + ([guid]::NewGuid().ToString('N'))
$RestoreDir = Join-Path $Root ('restore-check-' + $RunId)
New-Item -ItemType Directory -Path $RestoreDir -ErrorAction Stop | Out-Null
$ReceiptPath = Join-Path $RestoreDir 'restore-receipt.json'
$VolumeName = $null
$VolumeCreated = $false
$DestinationHost = $null
$Storage = 'bind'
if ($UseDockerVolume) { $Storage = 'docker-volume' }
$Receipt = [ordered]@{
    schema = 'clipforge-restore-check-1'
    patch = '0.4.2-restore-hotfix3'
    status = 'preparing'
    phase = 'destination'
    image_id = $Image
    archive_name = (Split-Path -Leaf $File)
    archive_sha256 = $Expected
    storage = $Storage
    volume = $null
    host_data_directory = $null
    container_data_directory = '/restore/data'
    hashes_match = $false
    timestamps_match = $false
    files = $null
    bytes = $null
    active_data_mounted = $false
    content_reviewed = $false
    created_utc = [DateTime]::UtcNow.ToString('o')
}
$Receipt | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $ReceiptPath -Encoding UTF8
try {
    if ($UseDockerVolume) {
        $VolumeName = 'clipforge-restore-check-' + $RunId
        $Existing = Get-DockerText -Arguments @('volume','ls','--filter',('name=^' + $VolumeName + '$'),'--format','{{.Name}}')
        if ($Existing) { throw 'El volumen destino ya existe. No se reutiliza.' }
        $Created = Get-DockerText -Arguments @('volume','create','--driver','local','--label','clipforge.purpose=restore-check','--label',('clipforge.restore_id=' + $RunId),$VolumeName)
        if ($Created -ne $VolumeName) { throw 'Docker no devolvio el nombre del volumen solicitado.' }
        $VolumeCreated = $true
        $Receipt.volume = $VolumeName
        $WriteMount = 'type=volume,source=' + $VolumeName + ',target=/restore,volume-nocopy'
        $ReadMount = $WriteMount + ',readonly'
        Write-Host ('Volumen NUEVO: {0}. No es el volumen de la aplicacion.' -f $VolumeName)
    } else {
        $DestinationHost = Join-Path $RestoreDir 'data'
        $Receipt.host_data_directory = $DestinationHost
        $WriteMount = 'type=bind,source=' + $RestoreDir + ',target=/restore'
        $ReadMount = $WriteMount + ',readonly'
        Write-Host 'Destino en carpeta del host. Si falla la precision temporal, usa -UseDockerVolume.'
    }
    $Receipt.status = 'running'
    $Receipt.phase = 'restore'
    $Receipt | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $ReceiptPath -Encoding UTF8
    # Only the selected archive is mounted read-only; never mount the active data/ or .env.ai.
    $ArchiveMount = 'type=bind,source=' + $File + ',target=/backup.zip,readonly'
    $RestoreArgs = @('run','--rm','--pull','never','--network','none','--workdir','/app',
        '--entrypoint','python','--mount',$ArchiveMount,'--mount',$WriteMount,
        $Image,'-m','app.backup','restore','/backup.zip','--destination','/restore/data','--sha256',$Expected)
    & docker @RestoreArgs
    if ($LASTEXITCODE -ne 0) { throw 'Restore no completado. No se desactiva la validacion de fechas ni hashes.' }

    # A SECOND container reopens the destination read-only and verifies the persisted files.
    $Receipt.phase = 'verify-restored'
    $Receipt | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $ReceiptPath -Encoding UTF8
    $HelperMount = 'type=bind,source=' + $Verifier + ',target=/checks/verify_restore.py,readonly'
    $VerifyArgs = @('run','--rm','--pull','never','--network','none','--workdir','/app',
        '--env','PYTHONPATH=/app','--entrypoint','python','--mount',$ArchiveMount,
        '--mount',$ReadMount,'--mount',$HelperMount,$Image,'/checks/verify_restore.py',
        '--archive','/backup.zip','--root','/restore/data','--sha256',$Expected)
    $VerificationJson = Get-DockerText -Arguments $VerifyArgs
    Write-Host $VerificationJson
    $Verification = $VerificationJson | ConvertFrom-Json
    if ($Verification.status -ne 'ok' -or $Verification.hashes_match -ne $true -or $Verification.timestamps_match -ne $true) {
        throw 'El verificador no confirmo integridad y fechas exactas.'
    }
    $Receipt.status = 'verified'
    $Receipt.phase = 'completed'
    $Receipt.hashes_match = $true
    $Receipt.timestamps_match = $true
    $Receipt.files = $Verification.files
    $Receipt.bytes = $Verification.bytes
    $Receipt | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $ReceiptPath -Encoding UTF8
} catch {
    $Receipt.status = 'failed'
    $Receipt | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $ReceiptPath -Encoding UTF8
    Write-Host ('Prueba fallida. Evidencia: {0}' -f $ReceiptPath)
    if ($VolumeCreated) { Write-Host ('Volumen de prueba conservado: {0}. No se borro ningun volumen automaticamente.' -f $VolumeName) }
    throw
}
Write-Host 'Restore verificado: hashes SHA-256 y fechas exactas. No se modifico la instalacion activa.'
if ($UseDockerVolume) {
    Write-Host ('Datos restaurados: volumen {0}, subcarpeta data/. No aparecen como data/ en el Explorador de Windows.' -f $VolumeName)
    Write-Host 'Conserva el volumen: no ejecutes volume prune. No copies estos datos a NTFS esperando conservar los nanosegundos.'
} else {
    Write-Host ('Datos restaurados: {0}' -f $DestinationHost)
}
Write-Host ('Evidencia: {0}' -f $ReceiptPath)
Write-Host 'Falta abrir y revisar un proyecto en una instalacion aislada. No hubo inferencia, render ni promocion de datos.'
