# SEC-01: remediación mínima y comprobaciones locales

Fecha local: 2026-11-09 (Guatemala); los últimos scanners registran
2026-11-10 UTC. **CI sigue bloqueado. GitHub Actions no se ha ejecutado.**
El desarrollo continúa en `C:\Users\itres\Desktop\clipforge-mvp`.
No se cambió, reconstruyó, detuvo o promovió el servicio operativo. Tampoco
se leyó contenido operativo, credenciales, variables del contenedor o backups.
Se conservaron las fuentes operativas de app y mantenimiento; la modificación
de `requirements.txt` afecta futuras construcciones, no el contenedor actual.

## Evidencia e identidades

Los 29 archivos de `.ci-local/ci01-ba2ee8bc/` conservan tamaños y SHA-256.
La verificación está en `baseline-preservation-verification.json` del expediente
nuevo `.ci-local/sec01-06e7d342/`. No se sobrescribieron informes CI-01 ni los
intentos SEC-01: `iteration-1` a `iteration-4` conservan fallos y correcciones.
El resultado final funcional está en `iteration-4/`.

| Imagen | ID SHA-256 | SBOM Trivy |
|---|---|---:|
| CI-01 conservada | `740f08d13d6c5899fe26aabe892db87f08f6682f1153589a0b86ec8d4cdb9f33` | 331 componentes |
| SEC-01 CI | `1d784364d96432973fdd52e2eeb4c0cb94974490e9473544bb361a71eed0639b` | 343 componentes |
| SEC-01 navegador | `38d7f04281674ec3c1663104ef89c8488897486722ed9e5ca7401e87ed88542c` | 355 componentes |

Las etiquetas finales son `clipforge/ci:sec01-integrated-06e7d342` y
`clipforge/ci:sec01-browser-integrated-06e7d342`. Se escanearon los mismos IDs
que ejecutaron las pruebas; se contrastó `Metadata.ImageID` de Trivy con el
SBOM y los iidfiles. Los TAR y sus hashes pertenecen solo a estas imágenes.

Se mantuvo Trivy **0.76.2** por digest. Se descargó una base nueva, conservada
en `scanner-db/`, con metadata y SHA-256
`da5b3caa6239084e8b921ca0aee661f127c1d18d86b55c6594fad5d2b8dc02b0`;
UpdatedAt `2026-11-10T01:02:55.861099573Z`. La imagen CI-01 se reanalizó con
esa misma base, sin actualizarla entre imágenes. La comparación preserva
234 hallazgos/60 CVE del baseline: cero altas/bajas, sin cambios de severidad,
estado o fixed. Cambiaron referencias en 15 findings y UID de PkgIdentifier
en seis; sus PURL permanecen iguales. `db-detection-field-diff.json` conserva
el detalle, sin atribuir esos cambios de metadata a la remediación.

## Diagnóstico y cambios de dependencias

La [matriz inicial](SEC-01-matrix.md) se produjo antes de cambiar versiones:
234 filas y 60 CVE, con JSON/CSV, origen, source package, campos crudos presentes
o ausentes, introductor, dictamen oficial y pruebas. No se confundió
`DataSource` con `SeveritySource`, ni un fix de sid con uno de trixie.
El [diagnóstico OS](SEC-01-os.md) explica el grafo FFmpeg → libavformat → libxml2.
La matriz inicial se conserva como diagnóstico temporal; sus referencias a
pruebas entonces pendientes no sustituyen los resultados finales de aquí.

| Dependencia | Antes | Después | Justificación |
|---|---|---|---|
| python-multipart | 0.0.20 | 0.0.31 | Tres HIGH; 0.0.30 era suficiente para ellos, pero seguía afectada por GHSA-v9pg-7xvm-68hf, parcheada en 0.0.31 |
| Starlette | 0.46.2 | 1.3.1 | Menor versión que reúne los tres fixes HIGH verificados |
| FastAPI | 0.115.12 | 0.133.0 | Compatibilidad: 0.132.1 aún exige Starlette <1; 0.133.0 admite el conjunto corregido |
| annotated-doc | ausente | 0.0.5 | Nueva dependencia obligatoria de FastAPI |
| zlib1g Debian | `1:1.3.dfsg+really1.3.1-1+b1` | `1:1.3.dfsg+really1.3.1-1+deb13u1` | Backport trixie verificado en DSA-6613-1; dos HIGH |

Se conservaron las otras 34 versiones del lock app. FFmpeg, Whisper, PyAV,
Uvicorn, HTTPX y la base Python/OS no se actualizaron. La base sigue Debian 13
por el mismo digest y snapshot firmado. Los registros de resolución normal de
pip están en `resolution/`; no se usó `--no-deps`. Los locks con hashes provienen
de wheels descargados, sin editar hashes manualmente. Los TXT directos también
son constraints de instalación. `dependency-diff.json` registra los hashes.

Se incorporaron herramientas verificadas: Bandit **1.9.4**, Coverage **7.17.2**
y Playwright **1.64.1**, en `requirements-ci-tools.*`: 12 paquetes, dos compartidos
con app, diez adicionales. Se instalan en la misma imagen CI y se incluyen en
ambos scans. El target navegador añade ocho paquetes APT directos y cuatro
transitivos; los inventarios dpkg tienen 292 paquetes en CI y 304 en navegador.
No se ocultaron herramientas separándolas de la imagen analizada.

Playwright instala Chromium **156.0.8078.4**, revisión **1248**, Chrome headless,
FFmpeg auxiliar **n7.0.1-playwright-build-1013** y su Node **24.22.1**. El FFmpeg
de aplicación sigue siendo `/usr/bin/ffmpeg` **7.1.5**. El inventario suplementario
`final-browser-binary-inventory.json` conserva versiones y hashes de binarios
vendorizados: el SBOM basado en paquetes no acredita por sí solo cobertura de
vulnerabilidades de cada binario o biblioteca embebida. Esa limitación permanece
abierta, no constituye un resultado limpio de esos componentes.

## Comparación de vulnerabilidades con base idéntica

| Imagen | Hallazgos paquete/CVE | CVE únicos | CRITICAL | HIGH | Nuevos frente a CI-01 |
|---|---:|---:|---:|---:|---:|
| CI-01 reanalizada | 234 | 60 | 1 | 233 | — |
| SEC-01 CI | 226 | 52 | 1 | 225 | 0 |
| SEC-01 navegador | 228 | 54 | 1 | 227 | 2 de CUPS |

Las CVE restantes de CI están incluidas en las del navegador: no se suman las
columnas como si fueran vulnerabilidades independientes. Se corrigieron ocho
hallazgos y ocho CVE del baseline en ambas imágenes:

- multipart: CVE-2026-24486, CVE-2026-42561, CVE-2026-53539.
- Starlette: CVE-2025-62727, CVE-2026-48818, CVE-2026-54283.
- zlib1g: CVE-2026-76844, CVE-2026-85091.

Los 226 restantes de CI corresponden a 52 CVE de Debian sin fix trixie
publicado en la consulta oficial, incluida **CVE-2026-6653 de libxml2**.
No se removieron bibliotecas de FFmpeg ni se importaron paquetes de otra suite.
La alternativa inmediata es mantener el bloqueo y revisar backports oficiales;
una distribución o stack multimedia distintos requieren propuesta y autorización.

La imagen navegador añade `libcups2t64==2.4.10-3+deb13u2`, source package `cups`
con la misma versión. La dependencia directa del stage satisface Chromium.
Los dos hallazgos son de herramientas CI/sistema del navegador, no dependencias
Python de la aplicación:

| CVE / GHSA | Severity / SeveritySource / Status crudos | FixedVersion crudo | Verificación oficial y remedio |
|---|---|---|---|
| [CVE-2026-34980](https://security-tracker.debian.org/tracker/CVE-2026-34980) / [GHSA-4852-v58g-6cwf](https://github.com/OpenPrinting/cups/security/advisories/GHSA-4852-v58g-6cwf) | HIGH / nvd / affected | ausente | Upstream 2.4.17, sid 2.4.17-1; trixie sigue vulnerable. Mantener bloqueo |
| [CVE-2026-55453](https://security-tracker.debian.org/tracker/CVE-2026-55453) / [GHSA-7hqf-mfhx-7r3v](https://github.com/OpenPrinting/cups/security/advisories/GHSA-7hqf-mfhx-7r3v) | HIGH / ausente / affected | ausente | Upstream 2.4.20, sid 2.4.20-1; trixie sigue vulnerable. Mantener bloqueo |

No se redujo la severidad al nivel del advisory upstream. No se verificó una
explotación ni se declararon falsos positivos. Las opciones exigen un backport
aplicable o una revisión de alcance posterior, conservando lanzamiento real y
seis recorridos de navegador. No retirar `libcups` para intentar pasar.

`final-security-matrix.json` contiene las 226/228 filas completas con evidencia
cruda y enriquecimiento oficial, más CSV por imagen y agrupación por CVE en
`comparison-ci/` y `comparison-browser/`. La matriz inicial y sus caches
oficiales permanecen en `diagnosis/`. La comparación está en `final-comparison.json`.

## Pruebas ejecutadas y límites

Todos los tests de aplicación se ejecutaron sin red externa, claves o montajes
operativos, con raíz readonly, capacidades eliminadas y datos sintéticos en
tmpfs. No se usó Compose ni puertos publicados. Las API fixture usan loopback
y puertos efímeros dentro del contenedor; no se tomó 8080/8081 del host.
Las descargas de APT, wheels, navegadores y scanner/DB fueron preparación separada.

| Control obligatorio ejecutado | Resultado local final |
|---|---|
| Discovery completo y unittest | **480 IDs únicos, 480 ejecutados**, 0 fallos, errores, skips, expected failures o unexpected successes |
| Diferencia de inventario | 436 originales intactos; +27 HTTP, +9 runner navegador, +8 runner CI; 0 retirados; hashes en `test-inventory-diff.json` |
| Checks del runner | 11 PASS: aislamiento, FFmpeg, ffprobe, pip check, runtime, media, presentación, branding, inventario, completitud y cobertura |
| Nativos/render/recuperación | Checks reales de decode/VAD, media, render/subtítulos/branding; tests de backup/restauración con fixtures sintéticos, hashes y fechas; incluidos en suite, no datos del operador |
| Cobertura app + scripts | Líneas **3166/3960 = 79,95%**; ramas **901/1298 = 69,41%**; combinado **77,35%**; 0 exclusiones, sin umbral inventado |
| Navegador | **6/6 PASS**, 53 pasos HTTP reales +7 pasos smoke simulado; 0 bridges/timeouts |
| PowerShell y JS | Parser nativo de 9 PS1 y `node --check` de ambos JS: PASS; no ejecución de mantenimiento operativo |
| Workflow | Actionlint 1.7.12 final: salida 0 |
| Secretos | Gitleaks 8.30.1: salida 0, sin hallazgos, snapshot de 116 fuentes explícitas; no índice/historial Git |
| Validador exacto del workflow | Rechaza evidencia real por SAST; 22 casos de contrato sintéticos separados dan el resultado esperado, sin modificar reportes reales |
| SAST | Bandit 1.9.4: **salida 1, 47 LOW**, 0 errores; bloqueante |
| SBOM | Ambos generados, salida 0, IDs coincidentes con imágenes probadas |
| Vulnerabilidades | Trivy: salida 1 en baseline y ambas candidatas; bloqueo conservado |

Cobertura no incluye navegador, JS ni procesos hijos de los checks CLI; sí mide
el proceso unittest y sus threads. Quedan 794 líneas y 397 ramas sin ejecución
instrumentada. App sola: 89,80% líneas/78,81% ramas; scripts: 53,57%/48,77%.
Algunos helpers probados mediante subprocesos/copias muestran 0% en esta medición.
No se han excluido para subir el porcentaje.

Los seis recorridos son smoke (fetch simulado), workflow, editorial, delivery,
AI y operations (cinco HTTP directos sobre Uvicorn/API fixture aislada).
Los 60 pasos son pasos browser, no 60 tests unittest adicionales. Las respuestas
ASR/LLM siguen escritas como fixtures; no acreditan inferencia real o calidad
editorial. [SEC-01-testing.md](SEC-01-testing.md) detalla los contratos HTTP nuevos.
Los comandos y códigos de salida están en
`.ci-local/sec01-06e7d342/commands-and-results.md`; los controles del validador
están en `workflow-validation/`. Los casos sintéticos no validan Actions.

Se conservaron los intentos fallidos: tres expectativas nuevas HTTP corregidas
según contrato/RFC, perfil crashpad incompatible con raíz readonly resuelto con
XDG en tmpfs, y carrera del test editorial resuelta esperando el estado exacto
del editor. No se modificó lógica app, tolerancias ni controles para hacerlos pasar.

## SAST bloqueante y siguiente trabajo

Bandit escanea `app/` y `scripts/` con todas las severidades/confianzas e
`--ignore-nosec`, sin skips, exclusiones, baseline de supresión o exit-zero.
Los 47 LOW, todos de confianza HIGH, corresponden a 36 ubicaciones:
B101=7, B404=13, B603=16, B607=11; once llamadas reciben B603 y B607.
44 findings señalan archivos idénticos al snapshot CI-01; dos pertenecen al
runner browser nuevo; uno del runner CI tiene atribución temporal indeterminada.
No existía un baseline Bandit ejecutado con el que comparar resultados.

El primer cambio posterior propuesto es sustituir los siete `assert` de
`app/check_branding.py:54-60` por validaciones explícitas y probar también
`python -O`: el [plugin oficial B101](https://raw.githubusercontent.com/PyCQA/bandit/1.9.4/bandit/plugins/asserts.py)
explica que los asserts desaparecen con optimización. Se propone, no se implementa
dentro de la actualización de dependencias. No resolvería los otros 40 hallazgos.
B607 requiere revisar ejecutables y PATH confiable; B404/B603 requieren revisar
cada import y llamada con argumentos. `shell=False`, aliases o wrappers no son
una justificación para eliminar la alerta. Fuente:
[plugins oficiales](https://raw.githubusercontent.com/PyCQA/bandit/1.9.4/bandit/plugins/injection_shell.py).
El detalle de rutas/líneas está en el JSON Bandit conservado.

## Archivos de código y configuración cambiados

| Archivos | Motivo |
|---|---|
| `requirements.txt`, `requirements-ci.lock` | Bundle compatible de remediación y hashes reales |
| `requirements-ci-tools.txt`, `requirements-ci-tools.lock` (nuevos) | SAST, cobertura y browser fijados e inventariados |
| `Dockerfile.ci` | zlib corregida, instalación sin red, targets CI/browser, dependencias Chromium y XDG temporal |
| `Dockerfile.ci.dockerignore`, `scripts/prepare_ci_context.py` | Admitir exclusivamente los dos archivos de herramientas adicionales |
| `scripts/run_ci_tests.py`, `tests/test_ci_runner.py` | Discovery íntegro, cobertura y ocho regresiones adicionales |
| `scripts/run_ci_browser.py`, `tests/test_ci_browser.py` (nuevos) | Ejecución estricta y nueve regresiones del runner |
| `tests/test_sec01_http.py` (nuevo) | 27 regresiones HTTP/formularios |
| `tests/browser_operations.py`, `tests/browser_editorial.py` | HTTP directo en operations y sincronización precisa editorial |
| `scripts/build_security_matrix.py` (nuevo) | Generación offline del diagnóstico real |
| `.github/workflows/ci.yml` | SAST/cobertura/browser obligatorios, ambos SBOM/scans, base identificada y gates estrictos |
| `AGENTS.md`, `README.md`, `docs/CI.md`, `docs/PROJECT_STATUS.md`, `docs/SEC-01*.md` | Alcance, diagnóstico, resultados, comandos y límites actuales |

No se cambiaron `.gitignore`, `.dockerignore`, Dockerfiles/Compose operativos,
`requirements-test.txt`, scripts de mantenimiento o fuentes `app/`. La
verificación de 49 fuentes protegidas registra cero diferencias. Las fuentes
de tests y CI se cambiaron solo donde se enumera arriba.

## Pendientes de GitHub y decisión de seguridad

Falta ejecutar el workflow real sobre un commit autorizado y conservar el run,
artifact y SHA. Esta tarea no crea Git, remoto, commit o push. Allí deben probarse
checkout por SHA, `git ls-files`, disponibilidad/tiempos/espacio de Ubuntu,
descargas, publicación del artifact, cancelación, gate obligatorio y protección
de rama. El workflow no tiene permisos de publicación, identidad cloud o secretos.
No se implementó Terraform ni despliegue.

Antes de aprobar CI siguen bloqueantes los 226/228 findings HIGH/CRITICAL de OS,
los 47 LOW de SAST y cualquier error/paso obligatorio sin ejecutar. Se necesita
resolver o decidir un alcance posterior para los backports ausentes y las rutas
de subprocess; no se aplicaron excepciones. La promoción y evaluación de la
instalación operativa quedan fuera de SEC-01.
