# CI-01 / SEC-01 / SEC-02: pruebas aisladas desde fuentes

La primera ejecución real de GIT-01 fue
[42859254764](https://github.com/AldemaroCruz/ClipForge/actions/runs/42859254764),
commit `f0cdfd29107229761aa2663bae9fee36ffd89e33`. Falló preparando la DB Trivy:
`mkdir /cache/db: permission denied`, antes de tests o scans. No fue un rechazo
por CVE. [CI-FIX-01.md](CI-FIX-01.md) documenta la corrección de permisos,
comprobaciones y límites; no modifica los bloqueos Bandit/Trivy.

GIT-01 usa `ci/bootstrap-sec03` para la referencia inicial. El primer envío no
constituye aprobación de CI o release: Bandit/Trivy siguen bloqueando bajo las
reglas vigentes. Cualquier ejecución real de Actions debe identificarse por
commit y enlace al run; los resultados locales anteriores siguen siendo locales.
No hay publicación de imagen, OIDC, despliegue o Terraform en este workflow.

SEC-03 conserva esos controles sin modificar el workflow, Bandit o el validador.
Solo añade las dos correcciones acotadas y sus regresiones. El alcance técnico
local de SEC-02 terminó; eso no aprueba CI/release. La preparación de Git usa
selección explícita y requiere autorizaciones posteriores para init/add/commit/push.
Resultados nuevos e históricos separados: [SEC-03.md](SEC-03.md).

## Carpeta y estado

El desarrollo autorizado continúa en
`C:\Users\itres\Desktop\clipforge-mvp`. La copia de `source\repos\clipforge`
se conserva sin sincronizarla. No se necesita recuperar un ZIP ni el candidato
v0.5.0-rc1: no se recibieron sus workflows o Terraform. CI-01 parte de v0.4.2
con los hotfixes locales.

El operador confirmó Docker Desktop funcional, restauración con hashes/fechas
exactas y apertura de un proyecto recuperado. Esa evidencia previa se conserva;
no se volvió a acceder a sus archivos para desarrollar CI.

La comprobación previa de CI-01 consultó únicamente montajes y comando del
contenedor operativo. No hay montaje de código ni `--reload`; los cambios de CI
no actualizan ese contenedor. No se inspeccionaron sus variables de entorno.

**Estado de GitHub Actions: pendiente de ejecución en GitHub.** La presencia del
workflow y una ejecución local no validan el servicio de Actions. Tampoco
constituyen aceptación editorial, inferencia real o despliegue cloud.

SEC-01 continúa autorizado en esta misma carpeta. El diagnóstico, cambios,
resultados finales y bloqueos se documentan en [SEC-01.md](SEC-01.md).
El apartado de resultados CI-01 de abajo se conserva como registro histórico.

SEC-02 extrae el gate a `scripts/validate_ci_reports.py`, incorpora actionlint
obligatorio antes del build y conserva el bloqueo de SAST/Trivy. Se necesitan
`image-inventory.json` y `browser-image-inventory.json`, generados sin scanner
por `scripts/capture_ci_inventory.py` dentro de cada candidata. El validador
compara fuentes, LOC reales de Bandit, objetivos/paquetes Trivy y SBOM contra
esos inventarios. Los informes anteriores no se completan ni reparan.
Estado y evidencia actual: [SEC-02.md](SEC-02.md).

## Contrato del entorno

- Linux amd64, CPython 3.12 sobre Debian 13; imagen Python fijada por digest en
  `Dockerfile.ci`. La arquitectura se selecciona explícitamente al construir.
- FFmpeg y fuentes desde el snapshot Debian firmado `20261109T000000Z`. Se permite la
  fecha histórica con `Check-Valid-Until: no`; se conservan firmas obligatorias.
- `requirements-ci.lock` contiene 38 wheels con SHA-256, resueltos en un
  contenedor limpio desde PyPI público. No se leyó el runtime operativo.
- SEC-01 cambia únicamente FastAPI, Starlette, multipart y la dependencia
  obligatoria nueva `annotated-doc`; mantiene las otras 34 versiones del lock.
  Los TXT directos se aplican como constraints al resolver e instalar.
- `requirements-ci-tools.lock` fija 12 paquetes para Bandit, Coverage y
  Playwright, incluidos dos compartidos con la aplicación. Tiene hashes propios.
  Ambos locks se instalan en la imagen CI: las herramientas se inventarían y
  escanean junto a la aplicación, sin atribuirles un entorno independiente.
- El target `browser` añade Chromium y ocho bibliotecas APT a `ci`; recibe
  inventario, SBOM y escaneo propios. El target predeterminado sigue siendo `ci`
  mediante la etapa final `default`. FFmpeg/Whisper no se sustituyen.
- Los hashes son específicos del wheel seleccionado para CPython 3.12/Linux
  amd64; este archivo no promete instalarse en Windows u otra arquitectura.
- La preparación descarga wheels; la instalación usa `--no-index`, hashes y una
  instrucción de build sin red. Los checks funcionales ocurren posteriormente
  con `docker run --network none`.

La resolución inicial fija transitivas que antes no tenían lock. No se presenta
como igualdad con los paquetes de producción. Antes de renovar ese lock deben
repetirse imports nativos, WAV/MP4, remuestreo/VAD, media, render/subtítulos/branding
y toda la suite. Un conflicto de resolución o scanner se registra como fallo;
no autoriza omitir pruebas ni añadir excepciones. Los cambios de pins requieren
un hallazgo verificado o compatibilidad demostrada, como en SEC-01.

## Contexto permitido

`scripts/prepare_ci_context.py` prepara un directorio nuevo fuera del checkout
y escribe un manifiesto separado con inventario exacto, tamaños y SHA-256.
Solo considera archivos fuente directos de `app/`, `app/static/`, `scripts/`,
`tests/` y los ocho archivos raíz enumerados en `ROOT_FILES`. No recorre
directorios privados o desconocidos. Rechaza enlaces/reparse points en rutas
admitidas, cambios durante la lectura, destinos existentes e inventarios extra.

`verify` debe aprobar antes de construir. La imagen recibe los helpers y el
Dockerfile que inspeccionan las regresiones; no recibe `compose.runtime.yaml`,
locks operativos, `.env*`, datos o caché. El ignore particular de CI añade otra
allowlist. El `.dockerignore` operativo conserva su comportamiento.

El escaneo de secretos tiene otro snapshot: GitHub obtiene únicamente nombres
con `git ls-files -z` y `scripts/prepare_ci_scan.py` valida la lista completa
antes de abrir fuentes. Si se versiona a la fuerza un archivo privado, generado,
un video o un estado Terraform, el gate falla sin leerlo. Solo se permite el
ejemplo raíz `.env.ai.example`. También se comprueban componentes de ruta,
enlaces/reparse points y hardlinks antes de copiar bytes. El snapshot externo
incluye las fuentes versionadas admitidas, documentación y workflow, con un
manifiesto SHA-256. Gitleaks no recibe la raíz completa del checkout.

Localmente todavía no hay Git inicializado: para comprobar este mecanismo se
usa una lista explícita de fuentes permitidas, sin fingir un índice o historial
Git. El descubrimiento por `git ls-files` queda pendiente de ejecución en GitHub.

## Ejecución local en PowerShell

Los comandos siguientes crean recursos exclusivos. Requieren permisos del
entorno para el daemon Docker y las descargas públicas. No utilizan Compose,
no publican puertos y no montan la raíz del proyecto.

```powershell
$repo = 'C:\Users\itres\Desktop\clipforge-mvp'
$ciTemp = Join-Path ([IO.Path]::GetTempPath()) ('clipforge-ci01-' + [guid]::NewGuid().ToString('N'))
$context = Join-Path $ciTemp 'context'
$manifest = Join-Path $ciTemp 'context-manifest.json'
$results = Join-Path $ciTemp 'results'
$dockerConfig = Join-Path $ciTemp 'docker-config'
New-Item -ItemType Directory -Path $results,$dockerConfig | Out-Null
$dockerArgs = @('--config',$dockerConfig,'--host','npipe:////./pipe/dockerDesktopLinuxEngine')
$image = 'clipforge/ci:ci01-' + [guid]::NewGuid().ToString('N')

py -3.11 -B "$repo\scripts\prepare_ci_context.py" prepare --source $repo --destination $context --manifest $manifest
if ($LASTEXITCODE -ne 0) { throw 'Context preparation failed' }
py -3.11 -B "$repo\scripts\prepare_ci_context.py" verify --context $context --manifest $manifest
if ($LASTEXITCODE -ne 0) { throw 'Context verification failed' }

docker @dockerArgs build --platform linux/amd64 --target ci -f "$context\Dockerfile.ci" -t $image $context
if ($LASTEXITCODE -ne 0) { throw 'CI image build failed' }
docker @dockerArgs run --rm --pull never --network none --read-only --cap-drop ALL --security-opt no-new-privileges --tmpfs /tmp:rw,exec,nosuid,size=2g --mount "type=bind,source=$results,target=/ci-results" $image
if ($LASTEXITCODE -ne 0) { throw 'CI tests failed; inspect the new results directory' }
```

Python del host solo prepara/verifica fuentes; las pruebas de aplicación usan
Python 3.12 dentro de la imagen. En Linux el helper se ejecuta con `python` y no
se necesita la opción `--host` de Windows. No usar `scripts/Test-Image.ps1` o
`Prepare-Upgrade.ps1` como sustitutos: pertenecen al mantenimiento operativo.

## Gates y evidencia

`scripts/run_ci_tests.py` no importa la aplicación al importarse. Configura
datos y HF_HOME temporales nuevos antes de checks/discovery; nunca reutiliza
la ruta de datos recibida. Ejecuta `pip check`, `app.check_runtime`,
`app.check_media`, `app.check_presentation`, `app.check_branding` y todos los
`test_*.py`. Rechaza suites vacías, errores de discovery, fallos, skips,
expected failures y unexpected successes. El JSON contiene conteos y estados,
no valores de variables o transcripciones.

SEC-01 añade inventario de IDs únicos y su hash, comparación entre discovery y
ejecución, cobertura de líneas/ramas de `app` y `scripts` sin omisiones y SAST
Bandit con todas las severidades/confianzas e `--ignore-nosec`. No se establece
un porcentaje mínimo inventado: se exige una medición real válida. Bandit sí
bloquea ante cualquier finding o error. Véase [SEC-01-testing.md](SEC-01-testing.md).

El workflow también verifica PowerShell y sintaxis JavaScript. Las acciones
están fijadas por SHA; el token solo lee contenido. No hay secretos cloud/IA,
OIDC, push de imágenes o despliegue. El gate final exige éxito de los jobs
requeridos incluso cuando fueron omitidos o cancelados.

Actionlint 1.7.12 se prepara por digest desde la imagen oficial `rhysd/actionlint`;
el análisis corre sin red. Una fixture inválida debe devolver exactamente 1 y
el diagnóstico esperado; el workflow real debe devolver 0. La versión, hash del
workflow y ambos resultados se guardan en `actionlint-summary.json`. El upload
conserva los informes incluso cuando ese control temprano falla.

El gate versionado se ejecuta después de verificar nuevamente el contexto:

```text
python -B scripts/validate_ci_reports.py --reports <CI_REPORTS> --context <CI_CONTEXT> --output <nuevo-report-validation.json>
```

Exige el formato emitido por Bandit 1.9.4 y Trivy 0.76.2/CycloneDX 1.7, tres
objetivos (Debian, Python, Node) y paquetes completos. Verifica epochs Debian,
propiedades multivaluadas de capas y un solo ImageID. Un schema nuevo del
productor requiere revisar el contrato; no se acepta silenciosamente.
Los 40 tests de `tests/test_ci_reports.py` usan expedientes sintéticos rotulados
y no acreditan scanners limpios. Los resultados de cada scanner siguen siendo
obligatorios y los findings mantienen la política vigente.

Los scanners se descargan en preparación; Trivy prepara su base por separado.
Gitleaks y el análisis de vulnerabilidades/SBOM se ejecutan sin red sobre
fuentes permitidas o un TAR de la imagen CI, nunca sobre datos operativos ni
con acceso al socket Docker. Secretos encontrados y vulnerabilidades HIGH o
CRITICAL bloquean; no se ignoran vulnerabilidades sin arreglo. El JSON de ese
gate se limita explícitamente a HIGH/CRITICAL, sin prometer un informe de las
demás severidades. Se conserva inventario de paquetes en JSON y SBOM completo.
La base de vulnerabilidades cambia con
el tiempo: conservar su fecha junto a los resultados, no prometer hallazgos
idénticos entre fechas.

La suite usa Whisper y respuestas editoriales simuladas; los checks de
decoder/VAD y renders sintéticos sí ejecutan código nativo. Los seis escenarios
`browser_*.py` se ejecutan aparte mediante `scripts/run_ci_browser.py`, en el
target `browser`, sin red externa. Cinco usan HTTP real contra API fixture
aislada y smoke intercepta fetch explícitamente. Se rechazan puentes, cero pasos
y fallos/timeouts. Ningún test acredita calidad editorial o inferencia real.

Los artefactos solo salen de carpetas temporales creadas por CI. No se suben
`evidence/`, `test-evidence/`, `release/` o directorios de la instalación. No
existe autorización para commits, push o configurar un remoto en esta tarea.

## Resultados locales de 2026-11-09

**Estado: funcional aprobado; seguridad bloqueada; GitHub Actions pendiente.**

La imagen final `clipforge/ci:ci01-final-ba2ee8bc` tiene ID
`sha256:740f08d13d6c5899fe26aabe892db87f08f6682f1153589a0b86ec8d4cdb9f33`.
Se construyó desde un contexto externo de 76 archivos/728.893 bytes verificado
antes del build. La suite y los scanners corrieron sin red ni montajes de
operación; la preparación de paquetes y base de vulnerabilidades fue separada.

| Comprobación ejecutada | Resultado |
|---|---|
| Suite completa | 436 pruebas, 0 fallos/errores/omisiones; 23,019 s |
| Checks obligatorios | 8 aprobados: entorno, FFmpeg, ffprobe, pip, runtime/decoder/VAD, media, presentación y branding |
| Regresiones nuevas incluidas | 19 del runner, 20 del contexto y 15 del snapshot de secretos; fixtures sintéticos |
| PowerShell y JavaScript | Parser nativo de 9 scripts y sintaxis de los 2 JS aprobados; no se ejecutaron wrappers operativos |
| Workflow | Actionlint 1.7.12 real, con shellcheck/pyflakes, salida 0 |
| Secretos | Gitleaks sin hallazgos en snapshot permitido de 106 fuentes; localmente lista explícita, no índice Git |
| SBOM | CycloneDX con 331 componentes de la misma imagen final |
| Vulnerabilidades | Trivy salida 1: 234 hallazgos paquete/CVE, 1 CRITICAL y 233 HIGH; corresponden a 60 CVE distintos |
| Validador real del workflow | Rechazó los informes reales por las vulnerabilidades, salida 1 |
| Contrato del validador | 13 casos sintéticos separados: un expediente completo simulado pasa; 12 variantes incompletas/fallidas se rechazan. No alteran los informes reales ni se suman a las 436 pruebas |

El entorno nuevo usa Debian 13 porque la comparación inicial sobre Debian 12
reportó 258 hallazgos (8 CRITICAL, 250 HIGH). La transición solo afectó a CI,
conservó los siete pins directos y fue verificada repitiendo toda la suite,
decodificación/VAD y renders. No se cambió la imagen del servicio operativo.

El CRITICAL restante reportado corresponde a `libxml2`, CVE-2026-6653, sin
versión corregida indicada por esa base Debian. Python tiene seis HIGH:
`python-multipart==0.0.20` (CVE-2026-24486, CVE-2026-42561, CVE-2026-53539) y
`starlette==0.46.2` (CVE-2025-62727, CVE-2026-48818, CVE-2026-54283).
Son resultados del scanner sobre CI, no un análisis del servicio operativo ni
una demostración de explotación. No se usó `ignore-unfixed` o allowlists.

El siguiente incremento debe revisar el conjunto FastAPI/Starlette/multipart
y los hallazgos del sistema. FastAPI 0.115.12 restringe Starlette a `<0.47.0`;
forzar solo una transitiva violaría el contrato. Antes de actualizar, definir
versiones compatibles y repetir API/cargas, escritura atómica, rangos,
subtítulos, render, entrega, recuperación y todos los checks nativos. Esa
actualización no forma parte de CI-01 y necesita autorización adicional.

Los informes propios se conservan en `.ci-local/ci01-ba2ee8bc/` (ignorado por
Git): `test-summary.json`, `security-summary.json`, `trivy-high-critical.json`,
`sbom.cdx.json`, manifiestos, hashes, logs de build/tests y auditoría de fuentes.
`commands-and-results.md` registra los comandos locales y sus códigos de salida.
Whisper/LLM y algunos casos de enlaces/reparse se simulan explícitamente; no se
contabilizan como inferencia real o una restauración nueva de datos del operador.

## Referencias de herramientas y contratos

- [Seguridad de Actions](https://docs.github.com/en/actions/reference/security/secure-use)
- [Instalaciones pip con hashes](https://pip.pypa.io/en/stable/topics/secure-installs/)
- [Bases Docker por digest](https://docs.docker.com/build/building/best-practices/#pin-base-image-versions)
- [Gitleaks v8.30.1](https://github.com/gitleaks/gitleaks/releases/tag/v8.30.1)
- [Trivy v0.76.2](https://github.com/aquasecurity/trivy/releases/tag/v0.76.2)
- [Actionlint v1.7.12](https://github.com/rhysd/actionlint/releases/tag/v1.7.12)
- [Checkout v7.0.1](https://github.com/actions/checkout/releases/tag/v7.0.1)
- [Setup Python v7.1.0](https://github.com/actions/setup-python/releases/tag/v7.1.0)
- [Upload Artifact v7.0.2](https://github.com/actions/upload-artifact/releases/tag/v7.0.2)
