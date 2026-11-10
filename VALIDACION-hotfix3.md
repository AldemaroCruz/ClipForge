# ClipForge v0.4.2 — Validación del hotfix 3 de restauración

Fecha: 30 de octubre de 2026. Base: ZIP v0.4.2 más los archivos reales del hotfix 2,
ambos adjuntos a esta conversación. No se recibió el ZIP privado de respaldo del
usuario; no se inspeccionaron sus videos ni las fechas reales de su filesystem.

## Diagnóstico comprobado

El código original de `restore_backup` llama primero a `verify_backup`, incluyendo el
SHA-256 externo cuando se proporciona. Durante la extracción verifica los bytes, aplica
`os.utime(..., ns=...)` y exige igualdad exacta de `st_mtime_ns`. El mensaje reportado
corresponde a esta última comparación. `Test-Restore.ps1` original monta solamente la
carpeta de respaldos de solo lectura y una carpeta nueva de destino; no monta el `data/`
activo ni utiliza `volumes-from`. La publicación del destino ocurre después de todas
las verificaciones. Se revisó ese orden, no se asumió desde el mensaje de error.

Se reprodujo el mismo ValueError en Linux modificando **solo para esa prueba** `os.utime`
para redondear a intervalos de 100 ns. La recuperación no se publicó, se eliminó staging
y el ZIP conservó su hash y siguió pasando su verificación. Después se restauró el
mismo archivo sobre el filesystem local con precisión completa y pasó la validación.

El redondeo a 100 ns es una simulación de regresión, no una medición del NTFS o montaje
Docker/Windows del usuario. No se demuestra aquí cuál componente produjo su redondeo.

## Qué cambia

`Test-Restore.ps1` agrega `-UseDockerVolume` como alternativa explícita. Crea un volumen
nuevo único, usa la imagen instalada por ID y conserva la validación estricta existente.
No arranca, detiene ni reconstruye la aplicación. No reemplaza el modo carpeta por un
modo que ignore fechas. Se conserva el modo original cuando no se solicita el switch.

`scripts/verify_restore.py` es un nuevo verificador solo de lectura. Corre en un segundo
contenedor con los datos restaurados montados de solo lectura. Verifica el archivo ZIP,
el inventario exacto de archivos, sus tamaños, hashes y mtimes enteros. Detecta cambios
durante la lectura y rechaza archivos adicionales, secretos sueltos, symlinks y un lock
de aplicación en lo que debe ser una copia recién restaurada. No repara ni actualiza
registros. Usa los módulos de respaldo de la imagen instalada, con `PYTHONPATH=/app`.

`app/backup.py`, `app/ai_selection.py`, `app/lease.py`, Dockerfiles, Compose y requisitos
se compararon con el ZIP base y se conservaron byte por byte (evidence/change-audit).
El contrato de identidad de las propuestas, los JSON y la imagen instalada no cambian.
El paquete no incluye fuentes tipográficas, modelos, backups, datos o credenciales.

## Resultados ejecutados

| Prueba | Resultado y alcance |
|---|---|
| Suite de regresión e integración | **382 pruebas aprobadas**, 99.230 s, salida 0: 344 de v0.4.2, 13 de hotfix 2 y 25 nuevas. |
| Nuevas pruebas repetidas tras ajuste menor del mensaje de fallo del wrapper | **25 aprobadas**, 3.312 s; mensaje solo se muestra si el volumen se creó realmente. |
| Reproducción del fallo de fechas | Misma excepción con redondeo simulado; destino no publicado; ZIP y origen conservados. |
| Restauración precisa y verificación | Escritura y lectura reales en Linux; valores ns no divisibles por 100 conservados exactamente. |
| Corrupción y diferencias | Rechazos por hash externo incorrecto, bytes distintos de igual tamaño y misma fecha, cambios de tamaño, drift temporal y archivo faltante. |
| Inventario y seguridad | Rechazo de archivo adicional permitido/desconocido, credencial suelta, lock, symlink, raíz inexistente o enlace. |
| No sobrescritura | Destino existente rechazado; datos previos preservados. |
| No reparación silenciosa | Un mtime incorrecto continúa incorrecto después de ejecutar el verificador que lo rechazó. |
| Subproceso real | Helper Python ejecutado desde otra carpeta con PYTHONPATH explícito; éxito JSON y error con salida 1. |
| PowerShell | Cuatro comprobaciones estáticas del texto: destinos aislados, montaje solo lectura, red desactivada y ausencia de mutaciones del servicio. **No equivalen al parser nativo ni a ejecución PowerShell.** |
| Regresiones de render/entrega/recuperación | Incluidas en la suite; FFmpeg real con medios sintéticos y transcripciones/respuestas IA controladas. |
| Sintaxis Python | `compileall` correcto en los archivos Python nuevos. |

Evidencia numérica del caso de precisión:

```text
mtime_ns esperado:  1793368800123456789
mtime_ns restaurado en filesystem Linux local: 1793368800123456789
```

La prueba de redondeo no publica una copia; la prueba precisa devuelve hashes_match y
timestamps_match en true. `content_reviewed` e `ai_inference_tested` permanecen en false.

## Entorno y límites

Linux x86_64, Python 3.13.5. FastAPI 0.128.2, Starlette 0.50.0, Uvicorn 0.48.0,
Pydantic 2.13.5, httpx 0.28.1 y FFmpeg 7.1.5. Ver el JSON de entorno incluido.

**No se ejecutaron PowerShell, Docker, Docker Desktop/WSL2, un volumen Docker real,
Windows/NTFS, Whisper real ni llamadas a un proveedor de IA.** No están disponibles
PowerShell o Docker en este entorno. Un intento de obtener PowerShell fue bloqueado
por la conectividad disponible; no se considera instalado ni validado.

Las pruebas de archivos son reales sobre directorios Linux; simulan el papel de un
destino con precisión completa, no la orquestación Docker. Los comandos del wrapper
se revisaron estáticamente. El usuario debe ejecutar el parser nativo existente antes
de correr el script y confirmar la recuperación en su Docker Desktop.

No se hizo una nueva prueba de navegador. No se evaluó rendimiento de grandes backups,
retención, cifrado, restauración de datos corruptos lógicamente o tolerancia a fallos
de energía. Un hash no prueba autenticidad sin una referencia externa confiable.

## Evidencias incluidas

- `all-tests-hotfix3.log`: ejecución de 382 pruebas; los tracebacks inducidos son parte
  de tests de error, no deben confundirse con el resumen final OK.
- `restore-hotfix3-tests-final.log`: repetición final de las 25 nuevas.
- `precision-reproduction.json`: reproducción y resultados con booleanos de alcance.
- `change-audit-hotfix3.json`: módulos y configuración conservados.
- `environment-hotfix3.json`: entorno realmente usado.

## Aceptación pendiente en el equipo del usuario

Copiar ambos archivos de scripts, desbloquear el PS1, ejecutar el verificador nativo y
restaurar el ZIP existente con `-UseDockerVolume`. Deben pasar tanto la extracción como
la segunda verificación de hashes y mtimes. Conservar el volumen y su recibo; revisar
un proyecto en una instalación aparte antes de promocionar datos. La aplicación activa
permanece en su directorio actual y no necesita detenerse ni reconstruirse.
