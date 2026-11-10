# ClipForge v0.4.2 — Informe de implementación y pruebas

Fecha: 30 de octubre de 2026. Base real: `clipforge-mvp-v0.4.1.zip` adjunto a esta conversación. Se modificó ese código, no una reconstrucción a partir de capturas.

**Estado del hito: EN VALIDACIÓN.** Se entregan herramientas operativas y evidencia local. No se declara completada la aceptación de tres proyectos reales, la imagen exacta de Docker Desktop, un repositorio/CI conectado ni el piloto cloud.

## 1. Alcance implementado

- Respaldo offline con inventario explícito, archivos conocidos, streaming ZIP64, verificación SHA-256/CRC y exclusión de archivos de credenciales reconocidos. Restauración solo a carpeta nueva, sin mezclar ni sobrescribir `data/`.
- Conservación de bytes y `mtime_ns`. La selección IA utiliza la identidad temporal del original: restaurar únicamente sus bytes no bastaba para reabrir propuestas pendientes.
- Exclusión mutua de filesystem entre la API y el backup. El wrapper exige detener el contenedor; la nueva API mantiene el mismo lease. No es un lock distribuido.
- Métricas laterales de cola y etapas del procesamiento/render; panel `/ops`, tokens ya reportados por el proveedor, aprobados/fallos/espacio y registro explícito de minutos de revisión humana. Tiempos históricos ausentes se muestran como no medidos; costo monetario no calculado, no cero.
- Captura del runtime y modelo del contenedor existente, actualización heredando esa misma imagen, comprobación de versiones y guardado opcional del artefacto local. No se inventan versiones, hashes o digests de la máquina del usuario.
- Fijación de la revisión del modelo descargado y hashes de sus archivos. Con lock activo se falla si faltan/no coinciden; no se cambia de modelo silenciosamente. Recuperación por descarga solo con comando explícito.
- Auditor de aceptación sin inferencia: comprueba una entrega ya existente, procedencia IA/borrador/revisión, hashes del ZIP y decodificación real del MP4. La declaración editorial del operador se registra separada.
- Runbook PowerShell, pruebas sobre imagen derivada sin alterar dependencias de producción, sello de imagen y rollback de código. Roadmap y backlog dentro del proyecto actualizados con pendientes, no marcados como finalizados por existir código.

**No cambia el selector/editor de IA ni sus proveedores, no publica clips y no despliega recursos cloud.** No se incluyeron datos del usuario, claves, modelos ni fuentes tipográficas.

## 2. Pruebas ejecutadas aquí

| Comprobación | Resultado real y alcance |
|---|---|
| `python -m unittest discover -s tests -v` | **344 pruebas aprobadas, 0 omitidas; 60.802 s**. Las 289 regresiones anteriores y 55 nuevas. |
| Backup/restore | Bytes/hash/mtime, ZIP alterado, rutas inseguras, duplicados, enlaces, archivos desconocidos, credenciales excluidas, límite de espacio, cambios durante la copia, estado activo y rechazo de destino existente. Fixtures, no videos privados. |
| Lease | Exclusión en el mismo proceso y en proceso separado; API activa rechaza un segundo propietario en el filesystem Linux de pruebas. No acredita el montaje Windows/WSL2. |
| Recuperación integrada | **FFmpeg real**: fuente sintética de 61 s y transcripción escrita → respuesta IA controlada → borrador → exportación → aprobación → ZIP → auditor con decodificación completa → backup → restore → API restaurada. |
| Reutilización IA tras restore | Se abrió el borrador previo y se aceptó una propuesta del análisis que NO había sido aceptada antes del backup. No hubo nueva consulta al modelo. Esto verifica el fingerprint que depende de `mtime_ns`. |
| Métricas | Escritura lateral, duración por etapa, falta de mediciones legacy, tiempo humano idempotente, conflicto 409, JSON inválido, errores sin texto de transcripción, contadores de tokens, actividad de análisis y promedio no calculado sin sesiones. |
| Modelo fijado | Cache sintética con blobs/enlaces internos, revisión explícita, hashes incorrectos/archivos faltantes/escapes rechazados; comandos verify y fetch con consentimiento. No se descargó ni ejecutó un modelo real. |
| Auditor de aceptación | Procedencia y revisión/ZIP, hashes, ausencia de artefactos, corrupción y decodificación fallida. El fixture de recuperación **no** se marca como aprobación humana. |
| `app.check_media` | **6 casos reales aprobados**, FFmpeg/ffprobe. |
| `app.check_presentation` | **10 comprobaciones reales aprobadas**, encuadres/audio/subtítulos/tamaño/color en píxeles. |
| `app.check_branding` | **6 configuraciones de render reales aprobadas**, posición/margen/contorno. |
| Sintaxis | Python `compileall` de app/tests/scripts y `node --check` de los dos JS: aprobados. No incluye parser/ejecución PowerShell. |
| Auditoría de cambios | Dockerfile/Compose/requirements originales y módulos editoriales, de IA, render y persistencia enumerados en `change-audit.json`: conservados byte por byte. |

La primera ejecución detectó cuatro aserciones heredadas que esperaban `data/` totalmente vacío; se ajustaron para excluir únicamente el nuevo archivo de lease. La suite final completa es la registrada, no el resultado de ese intento preliminar. Los tests negativos generan tracebacks deliberados: el resumen final de unittest determina el resultado.

### Flujo real frente a simulaciones

El test nuevo de recuperación utiliza la API real, archivos reales, FFmpeg real, aprobación y ZIP real. **La transcripción y la respuesta de IA son fixtures escritos expresamente para el test.** No se presentan como inferencia real. Las regresiones heredadas de Whisper también usan simulaciones.

El auditor demuestra que los artefactos existen, se relacionan y pueden decodificarse. No puede demostrar por sí mismo la autenticidad de una inferencia pasada ni juzgar contenido, precisión del ASR o calidad editorial. El flag humano nunca se activa automáticamente por aprobar tests.

## 3. Navegador

| Escenario | Resultado |
|---|---|
| Smoke heredado | 7 comprobaciones con respuestas de API simuladas. |
| Editor/render heredado | 10 comprobaciones funcionales + nota del transporte. |
| Biblioteca/borradores | 12 comprobaciones funcionales + nota del transporte. |
| Plantilla/revisión/ZIP | 9 comprobaciones funcionales + nota del transporte. |
| Selección IA | 15 comprobaciones funcionales + nota del transporte; servidor HTTP de respuestas prefijadas, no modelo real. |
| **Operación nuevo** | **7 comprobaciones:** resumen de API real, tokens/estados, histórico no medido, POST de tiempo humano, layout móvil, persistencia tras reinicio real de Uvicorn y ausencia de errores JS no manejados. |

Se intentó navegación directa de Chromium a localhost: **bloqueada con `ERR_BLOCKED_BY_ADMINISTRATOR`**, salida 1 conservada. Después se utilizó el transporte de pruebas explícito: HTML/JS reales → binding Python → HTTP real de Uvicorn. No se alteraron políticas administradas del navegador. Los videos de escenarios editoriales son bytes reales entregados como data URLs.

Esto no valida transporte HTTP/Range directo del navegador, descargas nativas de localhost, cancelación fetch, Docker Desktop ni montajes WSL2. La API Range se comprueba por separado con TestClient. Las capturas de Operación muestran datos sintéticos rotulados, no consumo real del usuario. Escritorio y 390 px se inspeccionaron sin desborde horizontal.

## 4. Entorno de estas pruebas

Linux x86_64; Python 3.13.5; FastAPI 0.128.2; Starlette 0.50.0; Pydantic 2.13.5; Uvicorn 0.48.0; python-multipart 0.0.29; Requests 2.32.5; httpx 0.28.1; NumPy 2.3.5; Playwright 1.57.0; Chromium 144.0.7559.96; FFmpeg/ffprobe 7.1.5-0+deb13u1.

**No hay Docker, PowerShell, faster-whisper, PyAV, CTranslate2 ni ONNX Runtime instalados aquí.** `app.check_runtime` devuelve salida 1 por dependencias ausentes, correctamente registrado como negativo. No se pudo acceder a PyPI desde el contenedor por resolución DNS. No se ejecutaron wrappers PowerShell, imágenes Docker, descarga de pesos ni inferencias Whisper/OpenAI/Ollama. No se utilizaron API keys reales ni se envió material del usuario.

Por ello no afirmamos que la actualización propuesta ya haya pasado en Windows: se entrega una ruta comprobable y conservadora basada en la imagen que el usuario ya probó, pendiente de su ejecución. Sus resultados locales anteriores no se cuentan como pruebas nuevas de esta entrega.

## 5. Reproducibilidad: qué se congela y qué no

`Prepare-Upgrade.ps1` requiere el contenedor de confianza en ejecución y el modelo completo ya cacheado. Captura las versiones **instaladas** de todos los paquetes, Python, arquitectura, FFmpeg y revisión/hashes del modelo; etiqueta y comprueba el ID inmutable local de la imagen. `Dockerfile.runtime` hereda esa imagen y no instala dependencias. Los checks de runtime/render sí se ejecutarán durante el build de destino.

`runtime-requirements.txt` NO contiene hashes de wheels. No es una promesa de reproducción desde PyPI en cualquier arquitectura. El artefacto a conservar es la imagen y sus metadatos. `Seal-Release -SaveImage` permite guardarlo con checksum. El ID local `sha256` no se presenta como RepoDigest de registry; el registry y CI pertenecen a una etapa posterior.

El `Dockerfile` de desarrollo sigue disponible pero no sustituye la ruta congelada. No se ha creado un lock universal nuevo ni se ha actualizado una biblioteca para fingirlo. No se distribuye un lock de la máquina del usuario antes de capturarlo.

`Test-Image.ps1` crea una imagen de tests descartable: instala únicamente httpx/httpcore de pruebas en un directorio separado, comprueba las dependencias originales y ejecuta la suite sin red externa, secretos ni volúmenes del usuario. Su build requiere PyPI. **Este wrapper aún no se ejecutó aquí.**

## 6. Seguridad y límites operativos

- Solo localhost, un contenedor/proceso propietario de `data/`; no autenticación ni aislamiento multiusuario. Nada se publica ni despliega.
- El ZIP de respaldo **contiene contenido privado y no está cifrado**. Excluye nombres/rutas conocidos de credenciales, no detecta secretos escritos dentro de texto arbitrario. Copiarlo fuera del mismo disco, con control de acceso.
- SHA-256/CRC detectan corrupción; no acreditan autenticidad sin una referencia confiable. La restauración no repara JSON previo corrupto.
- Los límites de backup (100.000 archivos/500 GiB) son topes de validación, no un benchmark de ese volumen. No se ejecutaron pruebas de carga/escaneo de seguridad/SBOM.
- La copia con la API detenida y el lease reduce la concurrencia; no protege frente a herramientas externas que ignoren el lock o filesystem remoto sin garantías compatibles. La precisión temporal del destino se comprueba y se falla si no coincide.
- Las métricas son sobre artefactos presentes, no un ledger de facturación. El RSS corresponde a la API, no a FFmpeg ni al contenedor completo. Los tiempos interrumpidos no se inventan.
- El análisis IA sigue siendo opt-in; métricas/backup/auditor/tests no llaman al proveedor. La descarga de un modelo fijado es otro comando, con permiso explícito.

## 7. Evidencia incluida

`test-evidence/python-unittest.log`, `test-summary.json`, `environment.json`, `change-audit.json`, checks reales de media/presentación/branding, logs de escenarios de navegador, intento directo bloqueado, runtime negativo y `syntax-check.log`. Son ejecuciones de v0.4.2; no se copiaron logs exitosos de v0.4.1. Las pruebas browser se cuentan como pasos de escenarios, no como pruebas unitarias extra.

## 8. Aceptación pendiente del operador

1. Esperar a que termine el trabajo; copiar el código conservando datos/cache/configuración. **No hacer down ni reconstruir antes de Prepare-Upgrade.**
2. Preparar el runtime y backup desde la imagen actual, iniciar la nueva, verificar `/health` → 0.4.2 y `/ops`.
3. Ensayar restauración en carpeta aislada y comprobar proyectos/borradores/propuestas allí.
4. Completar tres videos hablados autorizados; al menos una entrega desde propuesta IA. Contrastar audio, títulos, cortes, subtítulos y ZIP. Registrar minutos de revisión.
5. Generar evidencia del auditor, ejecutar regresiones contra la imagen capturada, guardar el artefacto identificado y revisar CI/scan antes de cerrar el hito.

Los comandos detallados, recuperación de errores y rollback están en `docs/OPERACION.md`. El roadmap queda **EN VALIDACIÓN**, no se avanza automáticamente a nube.

## Referencias técnicas primarias

Consultadas el 30 de octubre de 2026; sustentan interfaces utilizadas, no sustituyen validación del runtime.

- Docker Compose, build args/Dockerfile/red de construcción: https://docs.docker.com/reference/compose-file/build/
- pip, instalaciones repetibles y bundles: https://pip.pypa.io/en/latest/topics/repeatable-installs/
- pip, límites y hashes de instalaciones seguras: https://pip.pypa.io/en/stable/topics/secure-installs/
- Hugging Face, snapshot por revisión y cache: https://huggingface.co/docs/huggingface_hub/en/package_reference/file_download
- Hugging Face, snapshots/blobs de cache: https://huggingface.co/docs/huggingface_hub/en/guides/manage-cache
