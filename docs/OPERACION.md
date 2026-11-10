# ClipForge v0.4.2 — Actualización, respaldo y aceptación

Estado: código preparado; aceptación de la imagen exacta y tres proyectos reales pendiente en el equipo del operador. Sin despliegue cloud ni cambio de proveedor/modelo editorial. Solo Windows + Docker Desktop (contenedores Linux) y montajes estándar del MVP.

## 1. Actualizar sin volver a resolver dependencias

**No hagas `down`, `up --build`, limpieza de imágenes ni `docker system prune` antes de preparar.** Necesitamos el contenedor actual v0.4.1 en ejecución y su imagen. Espera a que terminen análisis, renders, cargas y entregas; cierra otras pestañas del editor durante mantenimiento.

Extrae el proyecto a una carpeta temporal y copia su contenido sobre la carpeta existente, conservando `data/`, `cache/`, `.env`, `.env.ai`, `release/`, `backups/` y `evidence/`. No hay esos datos personales dentro de este paquete. Respalda configuraciones propias antes de reemplazar código. No crees `clipforge-mvp/clipforge-mvp`.

Desde PowerShell en la carpeta del proyecto:

```powershell
.\scripts\Prepare-Upgrade.ps1
if (-not $?) { throw 'Revisa la preparacion antes de continuar.' }
.\scripts\Start-Release.ps1
Invoke-RestMethod http://127.0.0.1:8080/health
```

El primer script comprueba que no haya estados activos, detiene el servicio (no destruye su contenedor), conserva la imagen anterior bajo una etiqueta local derivada de su ID, inventaría las versiones Python de **esa imagen** y fija los hashes/revisión del modelo **ya descargado en tu caché**. Crea un respaldo verificado antes de publicar `compose.runtime.yaml`.

El segundo construye con `Dockerfile.runtime`, heredando el runtime conservado, comprueba que las versiones coincidan y ejecuta los verificadores nativos heredados. **No ejecuta pip install ni apt-get en la imagen de aplicación.** Copia únicamente el código nuevo y sus tests. Después inicia v0.4.2 con la configuración de IA existente si hay `.env.ai`.

La captura se guarda en `release/<fecha>-<id>/`:

- `runtime-lock.json`: Python, arquitectura, paquetes exactos y FFmpeg.
- `runtime-requirements.txt`: versiones transitivas instaladas; NO hashes de wheels.
- `model-lock.json`: revisión de Hugging Face y hashes de los archivos usados.
- `upgrade.json`: ID de la imagen anterior, ubicación del backup y estado **preparado, no aceptado**.

No hemos inventado hashes, digests o versiones para tu máquina. Los valores se obtienen allí. Los archivos de metadatos no contienen variables de entorno completas ni claves. La lista de paquetes es un inventario, **no una SBOM formal ni un escaneo de vulnerabilidades**.

La etiqueta local se comprueba contra el ID `sha256` de imagen capturado antes de construir. Un ID local no es un RepoDigest de registry. La reconstrucción desde fuentes/base pública aún no es totalmente hermética; esta ruta congela el artefacto que ya funcionó. No usar el Dockerfile de desarrollo para sustituir esta imagen sin validación.

### Fallos de preparación

Si falta la imagen, no hay contenedor en ejecución, la caché no contiene una revisión completa o `pip check` falla, el script se detiene. No sustituye el modelo ni actualiza librerías automáticamente. Conserva los mensajes, no compartas `.env.ai`. Si ya detuvo el servicio, puedes recuperar el contenedor anterior con:

```powershell
docker compose -f compose.yaml -f compose.ai.yaml start clipforge
```

Omite el segundo archivo solo en una instalación sin `.env.ai`. Los scripts PowerShell son fuente revisable y no están firmados. Si tu política bloquea scripts, revisa su contenido y sigue la política de tu equipo; no necesitas cambiar globalmente la política ni ejecutar como administrador.

## 2. Uso diario y métricas

Abre `http://127.0.0.1:8080` y recarga con Ctrl+F5. **Operación y métricas** abre `/ops`.

Las nuevas ejecuciones guardan tiempo de cola, validación, carga/verificación del modelo, transcripción, selección heurística y render. La IA conserva su tiempo total de análisis y tokens reportados. Los proyectos anteriores no reciben tiempos inventados. Se muestran espacio libre del volumen y RSS del proceso API; no representa toda la RAM del contenedor ni el pico de FFmpeg.

Los minutos humanos se introducen explícitamente por proyecto. Agregar un registro suma tiempo, no reemplaza el total. El mismo ID no duplica el registro si se repite la petición. Sin sesiones o aprobados no se calcula un promedio. No hay precio monetario configurado: `cost_usd` permanece nulo, **no cero**. La métrica no es una factura ni mide la calidad de los clips.

Después de probar la imagen, para iniciar sin reconstruir:

```powershell
.\scripts\Start-Release.ps1 -NoBuild
```

Las opciones equivalentes, cuando necesites comandos Compose, son:

```powershell
docker compose -f compose.yaml -f compose.ai.yaml -f compose.runtime.yaml ps
docker compose -f compose.yaml -f compose.ai.yaml -f compose.runtime.yaml logs --tail 100 -f clipforge
```

No expongas el servicio a Internet. Continúa sin autenticación y con un solo proceso Uvicorn.

## 3. Respaldo periódico

Espera todos los trabajos y deja de usar la UI; detén, **no elimines**, el contenedor:

```powershell
docker compose -f compose.yaml -f compose.ai.yaml -f compose.runtime.yaml stop clipforge
.\scripts\Backup-Data.ps1
.\scripts\Start-Release.ps1 -NoBuild
```

Cada backup guarda un ZIP64 privado y su `.sha256` externo en `backups/`. Usa streaming, verifica todos los hashes, conserva los tiempos de modificación exactos y rechaza estados activos. La API v0.4.2 y la CLI comparten un bloqueo de filesystem: no permiten dos propietarios simultáneos en el mismo filesystem local. La exclusión no es distribuida ni está validada aquí sobre el montaje Windows/WSL2. El wrapper también comprueba que el contenedor esté detenido.

Incluye archivos conocidos de proyectos, propuestas, borradores, estilos, revisiones y entregas; excluye archivos de credenciales reconocidos y la caché de modelos. Los archivos desconocidos/enlaces hacen fallar el backup, en lugar de crear una copia incompleta silenciosa. No busca ni elimina secretos que alguien haya escrito dentro de una transcripción o notas. Un JSON dañado puede respaldarse como bytes para recuperación forense, pero restaurarlo no lo repara.

El ZIP **no está cifrado** y contiene videos y transcripciones privados. Protege el acceso y copia ZIP + SHA-256 a otro dispositivo o almacenamiento autorizado. Una copia en el mismo disco protege una actualización, no un fallo físico. Un hash detecta corrupción; sin una referencia confiable no demuestra autenticidad frente a un atacante.

## 4. Ensayar restauración sin tocar los originales

```powershell
.\scripts\Test-Restore.ps1 -Archive .\backups\NOMBRE-REAL.zip
```

Se exige el `.sha256` externo. Crea `restore-check-<fecha>/data/`; el contenedor de recuperación **no monta el data/ original**. Rechaza destinos existentes, ZIP con rutas inseguras, entradas duplicadas/enlaces, tamaños o hashes diferentes. Verifica el contenido antes de publicar la carpeta y conserva `mtime_ns`: las propuestas IA actuales lo usan para reconocer el original. Un destino que no preserve esa precisión es rechazado.

No cambia tu instalación activa ni promueve automáticamente los datos restaurados. Comprueba biblioteca, un borrador, su MP4/SRT y una propuesta guardada en una instalación aislada antes de reemplazar nada. No edites simultáneamente la copia de prueba y la principal pretendiendo sincronizarlas.

La caché del modelo queda fuera del respaldo editorial. Con el lock conservado, si se pierde la caché puedes solicitar **explícitamente** la descarga de la revisión fijada:

```powershell
docker compose -f compose.yaml -f compose.ai.yaml -f compose.runtime.yaml exec clipforge python -m app.model_source fetch --allow-network
```

Este comando descarga pesos públicos, no sube videos ni llama a un LLM. Su disponibilidad depende del repositorio remoto. `verify` verifica hashes sin red. La aplicación no cambia a otro modelo ni descarga pesos al fallar un lock. Conserva también `release/` en un destino seguro para recuperar su descripción.

## 5. Aceptación real: tres proyectos

Usa tres videos hablados distintos, propios o autorizados; incluye uno representativo de un cliente. En al menos uno completa: carga → Whisper → autorización IA → propuesta → borrador → edición → MP4 → aprobación → ZIP. Escucha los cortes y contrasta títulos, transcripción, encuadre y contenido del ZIP. No sustituyas esta revisión por puntuaciones del modelo.

La nueva CLI NO crea contenido ni llama al proveedor. Verifica entregas existentes: origen de la propuesta, borrador, revisión, manifiesto/hash del ZIP y decodificación completa del MP4 con audio y video.

```powershell
.\scripts\Test-Acceptance.ps1 -ProjectId 6de6f90a1f5544da8a3bf491c7bc3002 -ContentReviewed
```

Usa el ID de un proyecto que hayas entregado y `-ContentReviewed` **solo después de revisarlo tú**. Sin esa marca o sin artefactos necesarios, el informe queda incompleto. La autenticidad de una inferencia pasada no se prueba mirando JSON: la aceptación registra qué existe y tu declaración humana por separado. Las pruebas con respuestas simuladas no acreditan modelos reales. `-Manual` valida una entrega manual, pero no cierra la aceptación IA del hito.

Las evidencias quedan en `evidence/`, con hashes e IDs pero sin texto de la conversación. No las sobrescribe. Cierra cambios sobre ese proyecto mientras se audita. No subas evidencia de cliente a un repositorio público sin revisar su contenido.

## 6. Regresiones en el runtime capturado e imagen identificada

Opcional, después de instalar:

```powershell
.\scripts\Test-Image.ps1
.\scripts\Seal-Release.ps1 -SaveImage
```

`Test-Image` crea una imagen **desechable** derivada de la imagen instalada; agrega httpx/httpcore de test en una ruta separada sin reemplazar los paquetes de producción. La construcción de esa imagen de tests necesita acceso a PyPI. Su ejecución usa `--network none`, no monta tus proyectos y no recibe tu API key. La suite usa respuestas IA controladas y no valida calidad editorial real. No despliegues la imagen de tests.

`Seal-Release` registra el ID exacto del artefacto local, compara paquetes/Python con el lock y opcionalmente exporta la imagen a TAR + SHA-256. **No declara una aceptación humana ni aprueba una nube automáticamente.** Conserva código, informe, locks, imagen y backup como piezas distintas. El TAR puede ser grande. Para cloud se promoverá esa imagen probada a un registry y se registrará su RepoDigest real.

## 7. Rollback de código

Con la v0.4.2 activa, sin trabajos en curso:

```powershell
.\scripts\Rollback-Release.ps1 -ConfirmRollback
```

Comprueba la identidad de la imagen anterior y la inicia sin reconstruir. No restaura ni mezcla data/. Los cambios son aditivos, pero **rollback de código no equivale a rollback de datos**. Si la API nueva no arranca, consulta `release/current.json`: la imagen anterior permanece disponible. No borres el respaldo ni hagas prune antes de cerrar aceptación.

## Pendiente antes de v0.5.0

Ejecución real de estos wrappers en Docker Desktop, corpus de tres videos, restauración allí, CI privado conectado, scan/SBOM formal y registro del artefacto aceptado. La entrega actual prepara herramientas; no acredita esas ejecuciones ni despliega recursos.

Fuentes técnicas consultadas para esta implementación: Docker Compose Build y especificación image/ID; pip Repeatable Installs y Secure Installs; Hugging Face snapshot_download con revisión. Ver TEST-REPORT.md. Ninguna de esas referencias sustituye probar la imagen objetivo.
