# SEC-01: contratos HTTP, navegador y cobertura

Fecha de preparación: 2026-11-09. Esta documentación describe el incremento de
pruebas; no certifica una ejecución en GitHub Actions ni una actualización del
servicio operativo. Los informes nuevos de SEC-01 deben conservarse separados
de `.ci-local/ci01-ba2ee8bc/`, que permanece como evidencia histórica.

## Inventario de referencia

CI-01 ejecutó **436 pruebas únicas**, sin fallos, errores u omisiones. Se
reutiliza su `test-summary.json`; no se repitió esa ejecución para contarla.
Los IDs se recuperan de `tests.stderr.log` tomando las líneas que comienzan con
`test_` y contienen el identificador entre paréntesis. No exigir el sufijo
`... ok`: algunas pruebas escriben logs entre el nombre y el resultado.

SHA-256 de los 436 IDs ordenados, UTF-8 y un LF después de cada ID:

`3cb6c00b4828be4584eb2c406f06fe13a436cb84585c951e0e1fe2d92037cf72`

| Módulo de CI-01 | IDs ejecutados |
|---|---:|
| test_ai_ranges | 28 |
| test_ai_selection | 46 |
| test_audio_check | 14 |
| test_ci_context | 20 |
| test_ci_runner | 19 |
| test_ci_scan | 15 |
| test_delivery | 40 |
| test_media | 26 |
| test_mvp | 34 |
| test_operations_042 | 54 |
| test_presentation | 19 |
| test_recovery_flow | 1 |
| test_restore_hotfix3 | 25 |
| test_runtime | 19 |
| test_smoke_transcribe | 7 |
| test_subtitle_style | 16 |
| test_upgrade_imports | 13 |
| test_workspace | 40 |

El total corresponde a 382 regresiones de producto/hotfix y 54 de CI-01:
19 del runner, 20 del contexto y 15 del snapshot de secretos. Un conteo AST de
funciones no sustituye este inventario de discovery y ejecución.

`scripts/run_ci_tests.py` ahora registra `test_inventory.ids`, módulos,
duplicados y el hash del inventario antes de que unittest consuma la suite.
Rechaza duplicados y exige que `tests_run` coincida con los IDs descubiertos,
además de todos los controles estrictos anteriores. Para comparar SEC-01 se
deben guardar los conjuntos exactos de IDs de ambos expedientes e informar
añadidos y retirados; una cifra total mayor no demuestra conservación de las
regresiones originales.

El alcance QA añade ocho métodos al runner, nueve gates del ejecutor browser y
27 contratos HTTP. Si no hay otros cambios, el discovery esperado es 480 IDs:
436 + 8 + 9 + 27. Es una expectativa de inventario, no un resultado ejecutado.
Los tests de otros trabajos SEC-01 deben explicarse aparte en la diferencia.

## Regresiones HTTP del cambio de dependencias

`tests/test_sec01_http.py` comprueba el parser multipart, el enrutamiento ASGI,
FileResponse y la persistencia reales mediante TestClient. Sus bytes de medios
y transcripciones son fixtures escritos; los hilos de procesamiento se
sustituyen para impedir inferencia o render accidental.

- Multipart: bytes/filename/opciones tipadas, archivo requerido, boundary
  ausente, números inválidos, restricciones de presentación, extensión,
  archivo vacío y límite exacto de tamaño/413 con limpieza del job nuevo.
- Errores: JSON 404, JSON 422 estructural, 503 con Retry-After y no-store,
  conservación de archivos ilegibles y ausencia de asignaciones prematuras.
- Descargas: bytes completos, disposition, prefijo/sufijo/rango abierto 206,
  416, rango malformado 400, unión de rangos solapados e If-Range con ETag.
- Editorial: cues guardados, validación estricta de opciones/revisión y
  consentimiento, borrador 201, actualización 200 y conflicto 409, sin cambiar
  originales. La metadata de duración del borrador se simula explícitamente;
  este fixture no acredita ffprobe.
- Límites URL-encoded: una app Starlette aislada exige `max_fields=2` y
  `max_part_size=4`. Cuenta nombres repetidos y bytes raw de nombre + valor,
  incluso `%XX`: `a=123` y `%61=1` pasan; `a=1234`, `%61=12` y tres campos
  devuelven 400. Es una regresión funcional del control corregido para
  CVE-2026-54283; no es una medición de complejidad o resistencia a DoS.

El 416 exige el contrato corregido de Starlette 1.3.1:
`Content-Range: bytes */128`, estado 416 y cuerpo vacío. Starlette 0.46.2 omitía
la unidad y devolvía `*/128`; se verificaron ambas implementaciones oficiales.
RFC 9110, sección 14.4, exige la unidad seguida del rango no satisfecho. Se
adopta una única expectativa exacta conforme al estándar; no se acepta el
formato antiguo como alternativa ni se modifica código de la aplicación.

Los errores de límite de campos pertenecen a una app **Starlette aislada**,
cuyo ExceptionMiddleware responde HTTPException mediante PlainTextResponse.
La expectativa inicial de JSON era incorrecta para ese fixture; ahora exige
400, `text/plain; charset=utf-8` y el mensaje exacto
`Too many fields. Maximum number of fields is 2.` para ambos cuerpos.
Los contratos JSON de los endpoints FastAPI de ClipForge conservan sus
assertions. Los límites de campos/bytes y todos los estados 400/416 siguen
siendo obligatorios.

La primera candidata SEC-01 ejecutó los 480 IDs completos, sin omisiones,
con todos los checks nativos y cobertura medida. Registró un fallo por el
formato antiguo de Content-Range y dos errores por intentar interpretar como
JSON esas respuestas de texto. Se preserva ese resultado rojo en
`.ci-local/sec01-06e7d342/iteration-1/`; estas correcciones de expectativas
nuevas requieren otra ejecución completa y no convierten retrospectivamente
esa primera ejecución en aprobada. Los controles funcionales ya habían
devuelto correctamente 416/400: las diferencias verificadas proceden del
contrato HTTP de la dependencia y del fixture Starlette, no de pérdida de
funcionalidad o relajación de límites en ClipForge.

No se cambian assertions existentes, umbrales, excepciones de scanners ni
pruebas de hashes/fechas. La selección de versiones compatibles pertenece al
diagnóstico de seguridad y sus locks; no se fuerza Starlette fuera del rango
permitido por FastAPI.

## Imagen y escenarios de navegador

La imagen browser es una etapa separada de CI sobre Python 3.12/Debian 13,
con herramientas en su lock independiente. Playwright 1.64.1 corresponde a
Chromium 156.0.8078.4, revisión 1248. La preparación descarga ese navegador;
los escenarios se ejecutan después sin red externa:

```text
PLAYWRIGHT_BROWSERS_PATH=/opt/ci-browsers python -m playwright install chromium
python scripts/run_ci_browser.py --report /ci-results/browser-summary.json
```

El primer comando pertenece exclusivamente a la preparación de la imagen,
no al contenedor de ejecución. No usar `--only-shell`: el runner obtiene
`playwright.chromium.executable_path` del navegador completo y lo comunica a
los scripts mediante `CHROMIUM_EXECUTABLE`. Verifica su versión contra el
`browsers.json` del paquete instalado y registra ambas versiones/revisión.

Las bibliotecas Chromium se obtienen de la matriz oficial para Debian 13 y
se instalan desde el snapshot firmado aprobado para CI. No añadir Firefox o
WebKit. Ejecutar con `--init --network none --shm-size=1g`, sin puertos
publicados, IPC del host ni montajes de código/datos operativos. No hace falta
usar 8080/8081: los servidores de los escenarios eligen puerto 0 en loopback
dentro del contenedor.

`run_ci_browser.py` copia únicamente fuentes directas de app, static, scripts
y tests a un workspace temporal nuevo. Cada escenario crea sus propios datos.
Los logs/screenshots generados salen a `browser-artifacts/` nuevo junto al JSON;
no se reutiliza un directorio de artefactos anterior. Un timeout termina solo
el grupo de procesos creado por ese escenario.

| Script | Transporte comprobado al ejecutarse | Contenido simulado |
|---|---|---|
| browser_smoke.py | HTML/JS reales, fetch reemplazado | Respuestas API; sin servidor real |
| browser_workflow.py | Navegador → HTTP Uvicorn → FFmpeg | Transcripción escrita; sin ASR |
| browser_editorial.py | Navegador → HTTP Uvicorn → FFmpeg | Transcripción escrita; sin ASR |
| browser_delivery.py | Navegador → HTTP Uvicorn → entrega/ZIP | Proyectos y medios sintéticos |
| browser_ai.py | Navegador → HTTP Uvicorn → stub HTTP local → FFmpeg | Respuesta LLM y transcripción escritas |
| browser_operations.py | Navegador → HTTP Uvicorn, reinicio del API | Métricas/consumo escritos; sin proveedor |

Operations ahora usa `/ops` por HTTP directo de forma predeterminada.
`CLIPFORGE_BROWSER_BRIDGE=1` conserva la alternativa histórica explícita; el
runner CI fija 0 y rechaza una salida que indique puente. No cambia a puente
si falla la navegación. Los seis scripts conservan sus assertions.

La primera ejecución browser con raíz de contenedor de solo lectura y XDG
aislado aprobó cuatro escenarios HTTP y el smoke; editorial se detuvo después
de ocho pasos al reutilizar una variante. Se preservan sus logs en
`.ci-local/sec01-06e7d342/iteration-3/browser-artifacts/`.
El test esperaba inmediatamente que `editorData.draft_id` fuera null, aunque
`openEditor` todavía esperaba el workspace por HTTP. El editor anterior ya
mostraba el mismo rango 3–10 y los mismos cues, así que esas comprobaciones no
distinguían la transición pendiente. La aplicación monta la copia con
`draft_id:null` después de esa respuesta; no se modificó esa lógica.

El escenario ahora pulsa el botón por nombre accesible exacto
`Usar estos ajustes` y espera el título visible
`Editar una copia de la variante` antes de las mismas assertions exactas de
rango, cues y `draft_id is None`. No se añaden sleeps, alternativas de éxito o
tolerancias. La primera descripción PASS también identifica condicionalmente
HTTP directo o el puente explícito según el transporte realmente configurado.
La corrección del test requiere otra ejecución real; no cambia el resultado
fallido conservado de la tercera iteración.

El resumen separa cinco escenarios HTTP de un smoke con API simulada. Los
`reported_steps` son mensajes de pasos, no tests unittest adicionales. Todos
los escenarios deben pasar; un exit 0 sin pasos, un timeout, un puente o una
dependencia ausente mantienen el gate rojo. Si falta el navegador, los
escenarios quedan bloqueados, sin fingir que se ejecutaron.

## Cobertura descriptiva

Coverage.py 7.17.2 se fija en el lock de herramientas; no se instala en el
servicio operativo. Con `--report`, el runner activa cobertura por defecto y
crea `<report-parent>/coverage/`; `--coverage DIR` permite elegir otro directorio
nuevo de artefactos. Una herramienta ausente o un informe fallido bloquea CI,
pero no oculta la ejecución de la suite.

La configuración programática es explícita: `source=[app, scripts]`, ramas
activas, `config_file=False`, `omit=[]`. Incluye fuentes sin ejecutar; no usa
exclusiones generales para mejorar el porcentaje. Produce `.coverage`, JSON
y XML. No existe un umbral histórico: `threshold` es null, no se inventa uno
ni se reduce uno existente.

La medición comienza antes de discovery y cubre unittest en el proceso actual,
incluidos sus threads. Incluye rutas ejercitadas con mocks. No incorpora los
subprocesos Python, checks nativos ejecutados como subprocesos, navegador ni
JavaScript, por lo que no equivale a cobertura completa del sistema. Esas
limitaciones figuran también en el JSON. El porcentaje inicial se registra
solo después de la ejecución real; no se estima a partir de los fixtures de
los tests del propio mecanismo de cobertura.

## Evidencia y comprobaciones pendientes

Los gates nuevos pueden probarse en el host con Python stdlib, `-B -S`, datos
temporales y ejecutores de checks/browser simulados. Eso acredita la lógica de
rechazo, el inventario y la gestión de artefactos, no la disponibilidad de
Playwright/Chromium, el HTTP real o un porcentaje de cobertura.

El expediente real SEC-01 debe registrar: imagen/digest, pins resueltos,
manifiesto de fuentes, IDs exactos y diferencia con CI-01, suite completa sin
omisiones, checks nativos, cobertura medida con sus límites, versiones de
browser, resultados de los seis escenarios y scanners de ambas imágenes.
GitHub Actions continúa pendiente hasta una ejecución real en GitHub.

## Fuentes primarias verificadas

- [Playwright 1.64.1 en PyPI](https://pypi.org/project/playwright/1.64.1/)
- [Manifest de navegadores 1.64.1](https://raw.githubusercontent.com/microsoft/playwright/v1.64.1/packages/playwright-core/browsers.json)
- [Dependencias nativas por plataforma](https://raw.githubusercontent.com/microsoft/playwright/v1.64.1/packages/playwright-core/src/server/registry/nativeDeps.ts)
- [Playwright en Docker](https://playwright.dev/python/docs/docker)
- [Instalación de navegadores](https://playwright.dev/python/docs/browsers)
- [Coverage.py 7.17.2](https://pypi.org/project/coverage/7.17.2/)
- [API pública de Coverage](https://coverage.readthedocs.io/en/7.17.2/api_coverage.html)
- [FileResponse de Starlette 0.46.2](https://raw.githubusercontent.com/encode/starlette/0.46.2/starlette/responses.py)
- [FileResponse de Starlette 1.3.1](https://raw.githubusercontent.com/Kludex/starlette/1.3.1/starlette/responses.py)
- [ExceptionMiddleware de Starlette 1.3.1](https://raw.githubusercontent.com/Kludex/starlette/1.3.1/starlette/middleware/exceptions.py)
- [RFC 9110, Content-Range](https://www.rfc-editor.org/rfc/rfc9110.html#section-14.4)
- [FormParser corregido de Starlette 1.3.1](https://raw.githubusercontent.com/Kludex/starlette/1.3.1/starlette/formparsers.py)
