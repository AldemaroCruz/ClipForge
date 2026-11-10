# ClipForge v0.4.2 — Validación del hotfix 2 de preparación

Fecha: 2026-10-30. Base: ZIP v0.4.2 adjunto y hotfix 1 adjunto. El cambio se hizo
sobre esos archivos, no se reconstruyó el proyecto desde el traceback.

## Resultado

**357 tests aprobados, 0 omitidos; 63.488 s** en la suite Python de esta ejecución.
Incluye 344 pruebas existentes y 13 nuevas. La ejecución independiente de las
13 nuevas pruebas también pasó (1.439 s). Logs íntegros en evidence/.

La suite existente contiene simulaciones explícitas de ASR/proveedor IA y pruebas
reales de FFmpeg, persistencia y API. No se presenta ese resultado como inferencia
real, validación de Docker Desktop ni garantía de compatibilidad de producción.

## Pruebas nuevas

- Reproducción real del `ModuleNotFoundError: No module named 'app'` al iniciar un
  archivo de script, con el mismo diseño app/ y scripts/ en un proceso Python hijo.
- Demostración de que cambiar solo cwd al padre no resuelve ese import.
- Invocación real del helper corregido con PYTHONPATH explícito: importación de
  app.backup/app.lease, lectura de datos sintéticos y conservación de hashes/mtime.
- Rechazo de estados queued/validating/transcribing/rendering/running, sin escribir
  en los datos. Estados completed/failed/interrupted siguen siendo legibles.
- Rechazo de carpeta faltante, archivo no permitido y app importada desde otra raíz.
- Comprobación de imports/CLI de capture_runtime.py y verify_runtime.py con --help;
  no es captura real de un modelo instalado ni comprobación completa del runtime.
- Backup -> verify -> restore reales por CLI Python, datos sintéticos, hashes y
  mtime idénticos. No se usó material del usuario.
- Aserciones de texto del contrato PowerShell: PYTHONPATH está limitado a los helpers,
  las correcciones del hotfix 1 permanecen y -CheckOnly sale antes de mkdir/stop.
  **Estas aserciones no equivalen a ejecutar ni parsear PowerShell nativo aquí.**

Los procesos nuevos se ejecutaron con `-S`, sin site-packages, para aislar las rutas
Python y comprobar que estas tareas requieren solo biblioteca estándar. Se usaron
rutas temporales con espacios. Son subprocesses reales en Linux, no contenedores Docker.

## Cambios exactos

Archivos existentes de v0.4.2 modificados: scripts/Prepare-Upgrade.ps1 y
scripts/check_idle.py. El verificador Test-PowerShellScripts.ps1 se conserva del
hotfix 1. Se añade tests/test_upgrade_imports.py. Los módulos app/, dependencias,
Compose, Dockerfile.runtime, Start-Release.ps1 y el pipeline no se modifican.
Se incluye un diff de Prepare respecto al hotfix 1 y una auditoría de cambios.

## Entorno y limitaciones

- Linux x86_64, Python 3.13.5.
- ffmpeg version 7.1.5-0+deb13u1 Copyright (c) 2000-2026 the FFmpeg developers.
- Paquetes: {"fastapi": "0.128.2", "starlette": "0.50.0", "pydantic": "2.13.5", "httpx": "0.28.1", "numpy": "2.3.5"}.
- Sin PowerShell ni Docker disponibles; no se ejecutó el contenedor objetivo,
  Docker Desktop, montajes Windows o scripts PowerShell nativos aquí.
- Sin inferencia real de Whisper ni proveedor IA. No se enviaron datos a proveedores.
- No se hizo una auditoría de seguridad ni se publicaron recursos cloud.

El nuevo -CheckOnly hace la comprobación de import/estado dentro del contenedor
auxiliar del usuario **antes** de detener el principal. La captura del modelo,
backup y build requieren la ejecución posterior normal; no se prometen aprobados
por el solo resultado del preflight.

## Fuentes primarias revisadas

- Python 3.12, inicialización de sys.path: https://docs.python.org/3.12/library/sys_path_init.html
- Python 3.12, ejecución por archivo y -m: https://docs.python.org/3.12/using/cmdline.html
- Docker run, --env y --workdir: https://docs.docker.com/reference/cli/docker/container/run/
