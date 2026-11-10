# SEC-04: detecciones y selección de ejecutables multimedia

Estado: incremento local revisable, sin commit, push, release ni promoción
operativa. CI-FIX-01 está cerrado: el run real
[42866539507](https://github.com/AldemaroCruz/ClipForge/actions/runs/42866539507)
del commit `2c5ea13e4c5935bad84a0ce7ad6c453fe221e52c` pasó permisos, tests y
browser; quedó bloqueado por Bandit/Trivy. SEC-04 no se ha ejecutado en GitHub.
Los resultados SEC-01/02/03 conservados son históricos.

## Detecciones antes del código nuevo

Se compararon JSON reales de Trivy 0.76.2, SBOM e inventarios independientes;
las filas se identifican por tipo de target, paquete, path, versión y CVE.
Se conservan campos ausentes, source package, origen, severidad y fuentes.
No se confunde un neto con el número de altas ni findings con CVEs únicos.

| Evidencia | Findings | CVEs únicos | HIGH | CRITICAL | Paquetes OS/Python/Node |
| --- | ---: | ---: | ---: | ---: | --- |
| SEC-02 CI | 226 | 52 | 225 | 1 | 292/49/1 |
| SEC-03 CI | 226 | 52 | 225 | 1 | 292/49/1 |
| SEC-02 browser | 228 | 54 | 227 | 1 | 304/49/1 |
| Actions CI | 266 | 62 | 265 | 1 | 292/49/1 |
| Actions browser | 268 | 64 | 267 | 1 | 304/49/1 |

SEC-03 no conserva un nuevo browser scan ni un nuevo inventario independiente
de CI; no se fabricaron. Su browser citado corresponde al histórico SEC-02.
Los inventarios SEC-02/Actions mantienen exactamente paquetes y versiones
(342 en CI, 354 en browser); también concuerdan Trivy y SBOM por imagen.

En cada imagen hay **40 altas, cero bajas y cero reclasificaciones de Severity
o SeveritySource**: diez CVEs de krb5 por cuatro bibliotecas ya instaladas,
`libgssapi-krb5-2`, `libk5crypto3`, `libkrb5-3`, `libkrb5support0`, versión
`1.21.3-5+deb13u1`. Son `CVE-2026-112315` a `CVE-2026-112323` y
`CVE-2026-119079`. En esas filas FixedVersion y SeveritySource están ausentes;
DataSource Debian se conserva por separado, sin inventar SeveritySource.

En comunes cambian VendorSeverity (15 filas CI/16 browser) y References
(19/20), pero no la severidad final, su fuente o FixedVersion. Fingerprints,
capas y metadatos de paquetes/SBOM también difieren; el delta exhaustivo los
conserva sin interpretarlos como versiones nuevas o regresiones de aplicación.

Las DB, ambas schema Version 2, se identifican por SHA256:

- SEC-02/03: `da5b3caa6239084e8b921ca0aee661f127c1d18d86b55c6594fad5d2b8dc02b0`,
  UpdatedAt `2026-11-10T01:02:55.861099573Z`.
- Actions: `c6512d0a28df88bc2d796b48792987f54a3e9a28704b35bb976bfab5460ee706`,
  UpdatedAt `2026-11-10T13:03:09.93195248Z`, DownloadedAt
  `2026-11-10T17:36:13.210181101Z`.

Las imágenes exactas de Actions no están en Docker local ni fueron publicadas
en un registry. Hay imágenes locales SEC-03 CI y SEC-02 browser y payloads de
ambas DB con hashes comprobados. La copia del payload B tiene otro DownloadedAt
local, que se conserva sin sustituir la metadata original de Actions.
El resultado de los controles causales y scans nuevos se registra al final de
este documento; no se atribuye una imagen local al ID de una imagen de Actions.

## CRITICAL y correcciones de la misma distribución

La consulta pública de la [API oficial Debian](https://security-tracker.debian.org/tracker/data/json)
del `2026-11-10T18:31:48Z` se filtró por los 64 CVEs y 17 source packages:
todos están `open` en trixie, sin `fixed_version`. No se modifican pins,
Dockerfile.ci, distribución o dependencias por un fix inexistente.

El CRITICAL sigue siendo libxml2/[CVE-2026-6653](https://security-tracker.debian.org/tracker/CVE-2026-6653),
instalada `2.12.7+dfsg+really2.9.14-2.1+deb13u3`, SeveritySource `nvd`;
la [API oficial NVD](https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-6653)
mantiene CVSS 3.1 de 9.8. El fix `2.14.5+dfsg-0.1` corresponde a sid/forky,
no a trixie. El vector secundario Ubuntu y una nota no-dsa no cambian el gate.
Los nuevos CVEs de [krb5](https://security-tracker.debian.org/tracker/source-package/krb5)
tampoco tienen un fix trixie verificado. CUPS sigue reportado y bloqueante;
no se convierte la ausencia del servicio de impresión en una excepción.

Decisiones pendientes: mantener el bloqueo hasta un fix firmado para trixie,
o autorizar por separado una evaluación de otra base/recompilación. Cambiar
distribución, recompilar multimedia o aceptar riesgo excede SEC-04. Ninguna
opción está aprobada por aparecer aquí; no se aplica VEX, ignore-unfixed,
exclusiones, rebajas o una DB antigua para obtener verde.

## Contrato de ejecutables y compatibilidad

La compatibilidad declarada es Docker en Windows/Linux/macOS; Windows usa
Docker Desktop con contenedores Linux. No se introduce `/usr/bin` en una ruta
de ejecución nativa Windows: el selector la rechaza explícitamente y explica
el entorno soportado. No se valida Python/FFmpeg nativos Windows en esta tarea.

`app/media_binaries.py` devuelve únicamente `/usr/bin/ffmpeg` o
`/usr/bin/ffprobe`. Rechaza nombres/ubicaciones ajenos, links y componentes no
regulares, propietario distinto de UID0, escritura de grupo/otros, setuid/setgid,
falta de permiso de ejecución y contenido sin cabecera ELF. Exige la ruta exacta
en `/var/lib/dpkg/info/ffmpeg.list`, con sus padres y archivo también confiables.
No usa PATH/PATHEXT, overrides de entorno, búsqueda alternativa ni cache que
salte la revalidación. El parámetro candidate solo valida la misma ruta exacta.

La lista dpkg acredita pertenencia declarada al paquete; no prueba resistencia
frente a un builder/root comprometido ni integridad criptográfica de APT por sí
sola. La candidata usa el mismo snapshot APT firmado y registra SHA256 real,
UID/GID/modo, paquete/version y lista dpkg en cada inventario. No hay garantías
de aislamiento del parser o de las bibliotecas cargadas añadidas por este cambio.

Antes de editar se siguieron 14 sitios de ejecución en acceptance, audio_check,
check_branding, check_media, check_presentation, check_runtime, media, render,
workspace y capture_runtime. Solo cambia argv[0]; no hay wrapper de subprocess,
shell, rediseño del renderer, cambio de formatos, argumentos o timeouts.
`main.ffmpeg()` sigue delegando. Los gates which existentes solo comprueban
presencia: sus resultados no seleccionan el ejecutable que se ejecutará.

El import del selector en capture_runtime es diferido a ffmpeg_version para
preservar los consumidores metadata-only run_tests/verify_runtime. La captura
mantiene el PYTHONPATH acotado que ya prepara Prepare-Upgrade; no se ejecutó
contra el servicio, su cache o un modelo. No se cambia ese script de despliegue.

## SAST: correcciones y decisiones sin aceptar riesgo

El análisis real nuevo con el mismo Bandit y comando de todas las severidades,
confianzas e ignore-nosec produce **28 LOW: 12 B404 y 16 B603; cero errores**.
Las once B607 anteriores desaparecen por selección explícita y validada, sin
renombrar imports, ocultar subprocess, cambiar reglas o aplicar excepciones.

- Defectos concretos corregidos: selección por PATH y falta de comprobaciones
  del ejecutable en los llamadores; se conserva la corrección SEC-03 de timeout,
  salida vacía y returncode. Se preservan los fallos, no se convierten en éxito.
- Evidencia insuficiente C01/C11/C12/C13: aceptación/ffprobe/render/thumbnail
  siguen procesando medios/artefactos del usuario. Protocol whitelist no acota
  las rutas legibles de `file`. Aprobar un modelo de aislamiento o demostrar
  esos límites es otra decisión; este selector no la resuelve.
  Se entrega una [propuesta separada, no implementada](SEC-04-media-isolation-proposal.md)
  con contrato y criterios de un futuro prototipo.
- Usos revisados: C02–C10 solo podrían plantearse individualmente para los
  llamadores de fixtures/versiones descritos en SEC-02; C14–C16 (pip/captura y
  runner browser) necesitan justificar intérprete/entorno/artefactos y límites.
  Chromium usa --no-sandbox dentro del contenedor: su política necesita una
  decisión específica, no una aceptación heredada de FFmpeg.
- B404: cada import necesita su propia revisión ligada a todos los subprocess
  de ese archivo. Aceptar una llamada no acepta el import ni otras llamadas.

La matriz nueva de 28 ubicaciones (`sast-locations.json/csv`) identifica regla,
ruta/línea, función, límites del span, SHA256 de archivo y span UTF-8/LF,
clasificación, decisión y condición de revisión. Todas constan **NOT APPROVED**;
responsable y aprobador están **UNASSIGNED**. Para una posible aceptación se
exige además alcance exacto, controles probados, riesgos residuales, entorno,
fecha de expiración y aprobación humana explícita. Un cambio de hash, llamador,
binario, dependencias, entorno o permisos obliga a revisar de nuevo. La ficha
histórica SEC-03-C02 ya no corresponde al hash nuevo y no se transfiere.

## Pruebas y trazabilidad local

Las candidatas CI/browser final4 se construyeron con contexto curado verificado
de 89 archivos, sin raíz del proyecto ni Compose operativo. No cambiaron el
workflow, helper de permisos CI-FIX-01, validador, dependencias, locks o base.
Todos los procesos de prueba/scanners usan recursos propios, UID1001:GID1001,
raíz RO, cap-drop ALL, no-new-privileges, inputs RO y red none. Las descargas de
preparación del browser son una etapa separada. No se usaron puertos del host.

Pasaron 24 regresiones dirigidas del selector. La suite integrada descubrió y
ejecutó **566 IDs únicos en 24 módulos**, sin fallos, errores, skips o expected/
unexpected failures: los 541 anteriores permanecen; se añaden 24 del selector
y uno de import metadata-only/verifier --help sin app/PYTHONPATH/lock/cache.
Hash del inventario: `5f277fc9ea759743b2816f6dcf28e8e2f48ed2010bf22e5abef7a183f702bffe`.
Pasaron 11 checks, incluyendo pip, imports/audio/VAD, media, presentación,
branding y completitud. La suite incluye render real y respaldo/restauración
con fixtures sintéticos; no mide ASR/LLM reales ni usa datos operativos.

Cobertura: 82.20108695652173% líneas, 71.98879551820728% ramas,
79.7056810403833% combinada; sin navegador ni subprocesos del checker.
Resolver: 37/37 líneas y 20/20 ramas. Seis escenarios browser pasan: cinco
HTTP directo sobre APIs aisladas y uno simulated_fetch; sin puentes o timeouts.
La confianza/permisos se prueba con árboles sintéticos; los inventarios de
ambas imágenes registran ejecutables reales. No se confunde una fixture con
un ataque explotado ni con el estado de Ubuntu/Windows operativo.

Expediente local nuevo: `.ci-local/sec04-94b062c8/`. Incluye comandos/salidas,
identidades de imágenes, manifiestos, comparación completa security/comparison-1,
fuentes oficiales cacheadas, test-inventory-delta, candidate-package-delta,
sast-locations y reportes nuevos. Se conservan intentos previos de build y el
rechazo inicial del manifiesto dentro del checkout; no se usan como validación
del código final. Los 38 fuentes Python finales coinciden byte/hash con ambos
inventarios y el contexto. Los informes previos no se sobrescribieron.

## Resultado de controles causales y scanners finales

Se ejecutaron seis scans JSON reales offline, sin refresh: dos DB por cada
imagen local conservada, y la DB B por cada candidata nueva. Los dos SBOM
nuevos se generaron por separado. El Trivy fijado por digest no cambió:
`ghcr.io/aquasecurity/trivy:0.76.2@sha256:6fa071ef8daa2e58b90cbf1710bedca91adbb3bf98693533226f442035b836a6`.
Las copias de DB se montaron RO; cache/scratch fueron recursos propios.

| Control de la misma imagen | DB A findings/CVE | DB B findings/CVE | Altas/bajas |
| --- | ---: | ---: | --- |
| CI local SEC-03 `ed3d85cc…` | 226/52 | 266/62 | +40/0, diez CVE añadidos |
| Browser local SEC-02 `297662ce…` | 228/54 | 268/64 | +40/0, diez CVE añadidos |

Los controles locales reproducen exactamente el aumento por cambio de DB,
manteniendo imagen, archive y paquetes constantes. No prueban una ejecución
de las imágenes GHA exactas con ambas DB: esas imágenes no están disponibles.
Las versiones de paquetes/inventarios GHA sí coinciden y no hay evidencia de
que el incremento de detecciones provenga de cambios de código.

| Candidata nueva (ID exacto) | Findings/CVE | HIGH/CRITICAL | SBOM libraries + OS |
| --- | ---: | ---: | ---: |
| `sha256:03cab9cc4ec69635736afe52a300a8ff7883cf05ce0c52f9eb536d8fb6ca5913` | 266/62 | 265/1 | 342+1 |
| `sha256:e7c8beccf65132d4568ebd673a525b83fb42cfa626727e3202fdc3abc244dfd4` | 268/64 | 267/1 | 354+1 |

Cada JSON identifica la imagen nueva correcta y su export tiene SHA256 propio.
Comparadas con GHA usando el mismo scanner y payload B: cero altas, bajas,
reclasificaciones Severity/SeveritySource/Status/FixedVersion/VendorSeverity,
cambios DataSource/source package o versiones. Cambian fingerprints/capas.
Todos los JSON terminan exit1 por hallazgos; ambos SBOM terminan exit0. No se
presenta ese exit1 como un fallo de permisos o un scanner incompleto.

Inventario completo: 38 paquetes de aplicación, 12 herramientas CI (11 Python,
incluido pip, y Node playwright-core), 292 paquetes OS compartidos y 12 extras
OS del browser. Hay 266 detecciones en OS compartido y dos adicionales del
browser; cero HIGH/CRITICAL detectados en los targets de aplicación/herramientas
CI. Esto clasifica introducción, no reachability ni uso exclusivo.
Se mantienen las limitaciones SCA de [SEC-02 OS](SEC-02-os.md): los metadatos
no acreditan cobertura completa de Chromium, Node y FFmpeg auxiliar
vendorizados. Cero detecciones de herramientas no demuestra ausencia de CVEs.

Bandit y Trivy continúan bloqueantes. El validador de reportes se ejecuta sobre
los informes nuevos y el contexto/snapshot exactos, sin cambios de lógica o
inventario tolerado; su resultado se conserva en `report-validation.json` del
expediente. Las fixtures sintéticas de tests y actionlint se mantienen aparte
de los informes reales de scanners. No se repiten CI-FIX-01 ni su run: el
workflow/helper mantienen sus bytes y la configuración de identidad/aislamiento.

## Propuesta de commit revisable

Un commit `fix(security): trust packaged media binaries and explain detection delta`
con el selector, sus 14 llamadores, inventario de binarios, tests y documentación.
Excluir por completo .ci-local y snapshots/reportes privados. No añadir pins,
Dockerfiles, Compose, workflows, excepciones o cambios de aislamiento. Revisión
del diff y scanner de secretos de la selección exacta antes de autorizar commit.
Esta entrega no crea commit, push, PR o release ni modifica la instalación activa.
