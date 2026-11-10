# SEC-02: validador estricto, actionlint y checker con optimización

10 de noviembre de 2026, Guatemala. **Este incremento no aprueba CI ni autoriza
release. GitHub Actions real sigue pendiente.** Se trabajó únicamente en
`C:\Users\itres\Desktop\clipforge-mvp`, sin sincronizar `source\repos`.

## Alcance y protección de la instalación

No se inició, detuvo, reconstruyó, reemplazó o actualizó el servicio operativo.
Docker Desktop no estaba disponible inicialmente; el usuario lo abrió. Antes
de integración se consultaron únicamente montajes y comando de su contenedor:
no hay montaje de código ni recarga automática. No se inspeccionó su entorno.
Solo se cambió `app/check_branding.py` dentro de `app/`, con autorización expresa.
No se accedió a datos, videos, cache, backups, release, credenciales o evidencias
operativas. Tampoco hubo consultas pagadas, commits, push, IAM o Terraform.

Los nuevos resultados están en `.ci-local/sec02-6a96aae0/`. Los informes
anteriores CI-01/SEC-01 se conservan; ningún intento nuevo reutiliza sus salidas.
Los JSON sintéticos del contrato están separados de `integration-1/`, que
contiene pruebas, inventarios y scanners reales sobre código nuevo.

## Reproducción y cierre de los tres bypasses

Se preservó el bloque original del workflow y se ejecutó completo sobre una
fixture positiva sintética y sus tres variantes. El bloque anterior aceptó las
tres; el nuevo las rechaza. **Son fallos del contrato, no evidencia de scanners
reales vacíos o fallidos.** Las fixtures se crearon desde cero, sin borrar
findings ni fabricar métricas de informes conservados.

| Variante, con el resto del expediente válido | Validador anterior | Nuevo |
|---|---|---|
| Bandit `results=[]`, `errors=[]`, sin métricas | Acepta | Rechaza |
| Bandit con cero líneas analizadas | Acepta | Rechaza |
| Trivy con ImageID correcto y `Results=[{}]` | Acepta | Rechaza |

Los tres negativos también son tests permanentes de `tests/test_ci_reports.py`.
Sus otros casos cubren tipos booleanos/strings/null incorrectos, esquemas
parciales, errores, omisiones, duplicados, identidad, cobertura, navegador,
secretos, actionlint, fuente alterada y paquetes faltantes.

`scripts/validate_ci_reports.py` reemplaza el bloque inline. Rechaza errores
de JSON, claves duplicadas y números no finitos; no modifica los informes.
Exige:

- Contexto verificado por hash; snapshot de secretos que cubra esas mismas
  fuentes y el workflow efectivamente analizado.
- Bandit 1.9.4: inventario exacto de todos los Python de `app/` y `scripts/`,
  métricas tipadas por archivo y totales coherentes, análisis no vacío, cero
  errores/skips/nosec y todos los hallazgos bloqueantes. Cada LOC se contrasta
  con el [algoritmo oficial](https://raw.githubusercontent.com/PyCQA/bandit/1.9.4/bandit/core/metrics.py)
  sobre las fuentes verificadas. Se calculan valores esperados para comparar;
  no se escriben métricas en un informe antiguo.
- Trivy 0.76.2: esquema 2 de imagen, identidad y OS correctos, objetivos Debian,
  Python y Node únicos y completos, paquetes no vacíos sin omisiones o extras,
  campos/versiones/PURL coherentes y bloqueo HIGH/CRITICAL intacto.
- Inventarios independientes de cada imagen mediante
  `scripts/capture_ci_inventory.py`: dpkg status, distribuciones Python instaladas,
  metadata npm del driver Playwright y hashes de las fuentes realmente copiadas.
  No se deducen paquetes esperados del informe Trivy que se está validando.
- SBOM completo de ese productor: CycloneDX 1.7/version positiva, ImageID único
  y el mismo inventario de paquetes. Los epochs Debian y los múltiples DiffID
  de capas se tratan conforme al formato real; no se colapsan ImageID ambiguos.
- Discovery y ejecución íntegros, returncodes nativos tipados, cobertura de
  todas las fuentes con totales/porcentajes coherentes, seis escenarios browser
  y sus prerrequisitos, sin bridges, y Gitleaks sin hallazgos.

Es un contrato del formato realmente emitido por versiones fijadas, no un
validador universal de todas las versiones de esos estándares. El inventario
Node independiente cubre la ubicación conocida del driver; nuevos objetivos
o paquetes detectados por Trivy bloquean al diferir. No acredita inventario de
todo código JavaScript o de bibliotecas embebidas arbitrarias. Los límites de
SCA de Chromium/Node/FFmpeg vendorizados siguen abiertos. El JSON no constituye
por sí solo una atestación criptográfica de ejecución del scanner.

## Actionlint obligatorio y temprano

Se añadió antes de preparar/build de la imagen, sin `continue-on-error`.
Versión **1.7.12**, imagen oficial
`docker.io/rhysd/actionlint:1.7.12@sha256:9d36088643581e728c969f35141f88139fec77280b2be23c1f66f8e40e1025e7`.
Se contrastaron RepoDigests y versión real, conservando las referencias de
[release](https://github.com/rhysd/actionlint/releases/tag/v1.7.12) y
[uso oficial por stdin](https://github.com/rhysd/actionlint/blob/v1.7.12/docs/usage.md).
La preparación con red y el análisis offline permanecen separados.

El workflow correcto debe salir 0. Una fixture con `runn` en lugar de `run`
debe salir exactamente 1 y emitir el diagnóstico esperado de step inválido.
Se probaron ambas condiciones con el binario real. Se ejecutó además el Python
exacto que produce `actionlint-summary.json`; conserva versión, hash del workflow
y ambos resultados. Los artefactos se suben aunque este control temprano falle.
Eso no acredita ejecución en GitHub Actions.

## Siete validaciones de branding

Los siete `assert` se sustituyeron únicamente por `if not <condición>` y
`raise AssertionError`, conservando los mismos mensajes, incluidos los dos
vacíos. No se cambiaron comparadores ni tolerancias. La equivalencia de las
condiciones se verificó por AST, antes de ejecutar las regresiones.

`tests/test_branding_checker.py` añade 11 IDs y 29 fixtures de límites:
13 válidas y 16 inválidas. La matriz completa se ejecuta normalmente y con
`python -O`; sus FFmpeg/render/pixels están simulados. El checker nativo real
se ejecutó aparte normalmente dentro del runner y con `python -O`, sobre MP4
sintético. No se confundieron esas dos clases de evidencia.

## Integración local nueva

Contexto externo permitido: **86 archivos / 888305 bytes**, verificado antes de
construir. No se envió la raíz del proyecto al daemon. Se construyeron imágenes
propias desde `Dockerfile.ci`; no se usó la imagen operativa, Compose, sus locks
o sus volúmenes. Raíz readonly, capacidades eliminadas, sin red externa ni
puertos publicados durante los tests; datos sintéticos en tmpfs.

| Imagen probada | ID |
|---|---|
| `clipforge/ci:sec02-integrated-6a96aae0` | `sha256:67d980855e13b8d1b007e02ec7a9d69e6047925bc58667b965961257d4ef1ff8` |
| `clipforge/ci:sec02-browser-6a96aae0` | `sha256:297662cef05c8ec8a7a859389762968eea8dc5077833e419a2bd01f5b4beca05` |

| Control sobre el conjunto integrado | Resultado |
|---|---|
| Discovery y suite completa | **531 IDs únicos descubiertos y ejecutados**, cero fallos/errores/skips/expected/unexpected |
| Diferencia real | 480 anteriores conservados; +40 contratos y +11 branding; cero retirados |
| Checks obligatorios | 11 PASS, incluidos pip, runtime/decoder/VAD, media, presentación, branding, inventario, completitud y cobertura |
| Branding optimizado nativo | `python -B -O -m app.check_branding`: 0, render/decodificación reales |
| Cobertura | Líneas **3543/4362 = 81,22%**; ramas **999/1408 = 70,95%**; combinado **78,72%**; cero exclusiones, sin umbral inventado |
| Navegador | Seis PASS: cinco HTTP directos contra Uvicorn/API aislada y un fetch simulado; 53 pasos HTTP +7 smoke, cero bridges/timeouts |
| Scripts y workflow | Parser de 9 PS1, ambos JS y actionlint del workflow: aprobados; fixture YAML inválida: salida 1 esperada |
| SAST | Bandit real: **40 LOW**, confianza HIGH, cero errores; salida 1 bloqueante |
| SBOM | Ambos nuevos, salida 0: 343 componentes CI y 355 browser, vinculados a sus IDs |
| Trivy CI | **226 hallazgos / 52 CVEs**, 1 CRITICAL y 225 HIGH; salida 1 |
| Trivy browser | **228 hallazgos / 54 CVEs**, 1 CRITICAL y 227 HIGH; salida 1 |
| Gitleaks 8.30.1 | Salida 0, cero hallazgos en 123 fuentes de lista explícita; no índice/historial Git |
| Validador real nuevo | Salida 1; exactamente tres bloqueos de findings: Bandit, Trivy CI y Trivy browser; sin errores adicionales de esquema/inventario |

La cobertura corresponde al proceso unittest y threads; no incluye browser/JS
o subprocesses de checks CLI. ASR/LLM siguen simulados, sin inferencia pagada
o aceptación editorial. Los 60 pasos browser no son 60 tests unittest adicionales.
`test-inventory-diff.json` contiene todos los IDs y hashes, sin usar un número
histórico como sustituto de discovery.

Trivy se ejecutó nuevamente sobre los TAR de las dos imágenes nuevas, sin red,
con la misma versión 0.76.2 y base congelada de SEC-01: SHA-256
`da5b3caa6239084e8b921ca0aee661f127c1d18d86b55c6594fad5d2b8dc02b0`,
UpdatedAt `2026-11-10T01:02:55.861099573Z`. No se descargó otra base ni se
atribuyó una variación de detección a código nuevo. Los hallazgos permanecen;
no hay remediación OS adicional en SEC-02.

Se conservó el primer intento de reproducción que falló por faltar un directorio
de la fixture (`app/static`); se corrigió el montaje de la fixture, sin cambiar
el contrato ni omitir pruebas. El preflight de formatos detectó propiedades de
capas multivaluadas válidas; se corrigió su interpretación y se añadieron
regresiones conservando el fallo original. Ningún fallo de preparación se presenta
como fallo del scanner o evidencia funcional nueva.

## Subprocess, CUPS y bloqueo OS

Bandit baja de 47 a 40 LOW por retirar las siete B101, sin nuevas alertas.
Siguen B404=13, B603=16, B607=11, en 29 ubicaciones. La clasificación exhaustiva
por ubicación, con entradas, ejecutable/PATH, argumentos, entorno, permisos,
timeout y límites está en [SEC-02-subprocess.md](SEC-02-subprocess.md).
No se cambiaron imports, wrappers, llamadas o políticas para esconder alertas.

Se proponen como defectos concretos un import sin uso (`app/main.py:13`) y una
captura sin timeout (`scripts/capture_runtime.py:65`), sin implementarlos aquí.
Las rutas multimedia requieren más evidencia de confinamiento/entradas; fixtures
y runners necesitan una decisión verificable de confianza y política. No se
plantea subir el umbral o aceptar B404/B603 en bloque.

[SEC-02-os.md](SEC-02-os.md) contrasta los avisos oficiales con archivos realmente
presentes. En la candidata browser conservada y, repetido después, en la imagen
final nueva: biblioteca cliente libcups presente y requerida por Chrome; daemon,
backend/filtros, configuración, PPD y spool no observados en 23 rutas/seis árboles
acotados. Eso limita la evidencia sobre las cadenas de impresión y no demuestra
"no afectado". CVE-2026-34980 no exige Foomatic; la RCE demostrada de
CVE-2026-55453 sí incorpora esa condición. Se mantienen ambos HIGH sin VEX,
excepciones, rebajas o retirar la biblioteca requerida.

La consulta oficial Debian actual conserva abiertos los 54 CVEs del browser,
incluidos los otros 52/226 hallazgos. Las opciones verificadas son conservar el
bloqueo y vigilar los 15 source packages restantes hasta un backport firmado
aplicable a trixie, con regresiones del grupo afectado. No se cambió distro,
snapshot, FFmpeg, Whisper, dependencias o locks; no se importó sid ni recompiló.

## Archivos para revisión y pendientes

- `app/check_branding.py`: siete validaciones equivalentes.
- `scripts/validate_ci_reports.py` y `capture_ci_inventory.py`: gate versionado
  e inventario independiente del scanner.
- `tests/test_ci_reports.py` y `test_branding_checker.py`: 51 IDs nuevos permanentes.
- `.github/workflows/ci.yml`: actionlint temprano, inventarios y llamada al gate.
- `AGENTS.md`, `README.md`, `docs/CI.md`, `docs/PROJECT_STATUS.md` y los tres
  `docs/SEC-02*.md`: alcance, clasificación, resultados y decisiones pendientes.

Los comandos/códigos de salida, manifiesto de fuentes, comparación SAST/SCA,
preservación y resultado real del gate se conservan en el expediente SEC-02.
Véanse `commands-and-results.md`, `security-summary-final.json`,
`integration-1/report-validation.json` y `review.patch` dentro de ese directorio.
Los resultados finales de scanners/gate deben leerse en sus JSON reales; las
fixtures positivas nunca sustituyen esos resultados. El bloqueo SAST/OS continúa.

Falta ejecutar el workflow en GitHub sobre un commit autorizado, conservar SHA,
run/artifacts y verificar runner/tiempos/espacio/protección de rama. También
quedan las decisiones de remediación/política subprocess y los backports OS sin
publicar. Cualquier promoción a la instalación activa es otra autorización.
