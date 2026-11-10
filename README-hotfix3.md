# ClipForge v0.4.2 — Hotfix 3: restauración en volumen aislado

## Alcance

Parche para una instalación **ya funcionando en v0.4.2**, tras los hotfixes de preparación.
No reinstala ClipForge, no reconstruye la imagen, no repite Prepare-Upgrade y no toca
`app/backup.py`, el contrato de IA, los locks de runtime ni las dependencias.

El modo nuevo es explícito: `-UseDockerVolume`. Sin ese parámetro se conserva la
restauración a carpeta del host, que puede seguir rechazándose por precisión temporal.
Esto ofrece una recuperación estricta en un destino distinto; **no convierte el montaje
Windows en un filesystem con precisión de nanosegundos ni reescribe las fechas de IA**.

## Qué falló

El restaurador verifica primero el ZIP y su contenido, y después exige que cada archivo
restaurado conserve `st_mtime_ns` exactamente. El error reportado aparece tras esa
verificación inicial, al comparar una fecha escrita con la fecha leída desde el destino.
No indica por sí mismo un ZIP corrupto. El proceso original no montó `data/` activo y
su bloque `finally` elimina el staging que no pudo publicar.

Python advierte que la resolución de fechas depende del sistema y el filesystem. La
capa Windows/Docker del destino es la hipótesis principal, pero aquí no se midió su
granularidad ni la diferencia numérica del archivo del usuario. No se atribuye el fallo
con certeza a NTFS, WSL2, VirtioFS u otro backend específico.

Las propuestas actuales usan la fecha exacta, el tamaño y la duración del original.
Ignorar esta comprobación podría permitir una copia cuyos análisis guardados luego se
rechacen. No se elimina el guard ni se edita `selection.json` para hacerlo pasar.

## Instalación: solo dos archivos

Descomprime en una carpeta temporal y copia el contenido de `scripts/` sobre:

```text
C:\Users\itres\Desktop\clipforge-mvp\scripts
```

- `Test-Restore.ps1`: reemplaza el anterior.
- `verify_restore.py`: archivo nuevo; también debes copiarlo.

Los tests, evidencias y esta documentación pueden conservarse aparte. No reemplaces
`Prepare-Upgrade.ps1`, `check_idle.py` ni otros scripts: este parche no revierte hotfix 2.
No requiere cambiar `.env.ai`, `compose.runtime.yaml`, `release/`, `backups/` ni `data/`.

Revisa el contenido y desbloquea únicamente el script descargado. En PowerShell:

```powershell
cd C:\Users\itres\Desktop\clipforge-mvp
Unblock-File -LiteralPath .\scripts\Test-Restore.ps1 -ErrorAction Stop
.\scripts\Test-PowerShellScripts.ps1
```

El verificador anterior debe mostrar nueve scripts correctos. Solo revisa sintaxis y
ciertos patrones, no ejecuta Docker. Si falla, no continúes.

## Ejecutar la recuperación aislada

Conserva ClipForge funcionando; no necesitas detenerlo para esta copia de prueba.
Usa el ZIP existente junto con su `.sha256`:

```powershell
.\scripts\Test-Restore.ps1 `
    -Archive ".\backups\clipforge-before-042-20261030-084026.zip" `
    -UseDockerVolume
```

El script identifica la imagen por su ID local SHA-256. No usa una etiqueta flotante,
no descarga otra imagen y comprueba que la instalada sea Linux. Crea un volumen local
con nombre aleatorio y etiqueta de prueba; no acepta un volumen existente como destino.

El primer contenedor temporal ejecuta el restaurador existente, con el ZIP seleccionado
montado como archivo de solo lectura y el volumen nuevo en `/restore`. No monta el
directorio activo, otras carpetas de proyectos, caché ni credenciales. No publica puertos.

El segundo contenedor abre el volumen **en solo lectura** y comprueba de nuevo inventario,
SHA-256, tamaños y fechas exactas contra el ZIP. Ambas ejecuciones usan `--network none`
y `--pull never`; no hay ASR, LLM, render, actualización de dependencias ni gasto cloud.

## Resultado esperado

Primero aparecerá el JSON del restaurador original. El segundo verificador debe incluir:

```json
{
  "status": "ok",
  "scope": "restored_bytes_and_exact_mtimes",
  "hashes_match": true,
  "timestamps_match": true,
  "content_reviewed": false,
  "ai_inference_tested": false
}
```

También incluye `files` y `bytes` reales. El mensaje final es:

```text
Restore verificado: hashes SHA-256 y fechas exactas. No se modifico la instalacion activa.
```

La recuperación queda en el volumen `clipforge-restore-check-<fecha>-<id>`, subcarpeta
`data/`. **Los archivos no aparecen como otra carpeta de videos en el Explorador de
Windows.** La carpeta local `restore-check-<fecha>-<id>/` guarda únicamente el recibo
`restore-receipt.json` cuando se utiliza el modo volumen. Este recibo identifica volumen,
imagen, ZIP y resultados, sin texto de transcripciones ni claves.

El volumen permanece después de eliminarse los contenedores temporales. Consume espacio
en el almacenamiento administrado por Docker Desktop. No es una copia en otro dispositivo.
Mantén el ZIP y su hash externo protegidos y conserva el volumen hasta revisar la copia.
No ejecutes `docker volume prune`, limpiezas generales ni el reseteo de Docker Desktop.
No copies la carpeta a NTFS suponiendo que conservará los nanosegundos: eso puede volver
a introducir el mismo problema.

## Si falla

No se promociona nada a la instalación activa. El recibo queda con `status: failed` y la
fase alcanzada. El volumen de prueba, si se creó, se conserva; no se borra ningún volumen
automáticamente. No uses un resultado parcial como recuperación aprobada. Comparte el
primer error y la fase; no compartas `.env.ai` ni el contenido privado del respaldo.

Una falla de precisión incluso en este destino seguirá siendo un error: no hay tolerancia
silenciosa. También pueden fallar falta de espacio, archivos faltantes, hash incorrecto
o permisos; el script no convierte esos casos en éxito.

## Lo que todavía no prueba

Esto valida bytes, inventario y fechas en la copia; no demuestra calidad editorial ni una
nueva transcripción. Falta abrir proyectos y una propuesta guardada en una instancia
separada que use ese volumen, sin promoverlo todavía ni tocar el servicio actual.

El arreglo permanente de portabilidad —usar identidad de contenido versionada, no una
fecha de filesystem, para vincular los originales— queda como deuda de arquitectura.
No se modifica ese contrato en este parche de recuperación.

## Fuentes primarias

- Python 3.12, resolución de stat/utime: https://docs.python.org/3.12/library/os.html#os.utime
- Docker, volúmenes, persistencia y volumen-nocopy: https://docs.docker.com/engine/storage/volumes/
- Windows, representación de tiempos: https://learn.microsoft.com/en-us/windows/win32/sysinfo/file-times

Consulta: 30 de octubre de 2026. Ver VALIDACION-hotfix3.md para pruebas y limitaciones.
