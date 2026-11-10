# SEC-01 — Matriz inicial completa de vulnerabilidades

Fecha de contexto: 2026-11-09. Diagnóstico ANTES de cambios de versiones. No acredita remediación, despliegue ni GitHub Actions ejecutado.

Imagen CI baseline: `sha256:740f08d13d6c5899fe26aabe892db87f08f6682f1153589a0b86ec8d4cdb9f33`; Debian 13.7/trixie. **234 hallazgos, 60 CVEs únicos**; 228 sistema y 6 app. No son 234 CVEs distintos.

La línea base `.ci-local/ci01-ba2ee8bc/trivy-high-critical.json` y su SBOM no se modifican. Esta matriz conserva cada hallazgo, agrupa por CVE y separa campos crudos del scanner de información resuelta con dpkg/SBOM o fuentes oficiales.

**Ausente** significa que la clave no existe en el registro de vulnerabilidad original; no se rellena `SeveritySource` con `DataSource`. `SrcName` resuelto desde otro inventario se muestra aparte. `FixedVersion` crudo ausente no se sustituye por un fix de otra suite ni por una versión upstream.

| Campo original | Registros donde está ausente |
|---|---:|
| SeveritySource | 175 |
| SrcName | 234 |
| FixedVersion | 226 |
| Status | 0 |
| DataSource | 0 |

## Fuentes y reproducción

Las respuestas oficiales se descargaron por HTTPS con HTTP 200 y fecha UTC, y se filtró la API de Debian a los 60 IDs de esta línea base. El JSON de la matriz conserva esas referencias y los datos por release. Los metadatos PyPI fijan la dependencia introductora y los GHSA del proyecto fijan rangos corregidos; los backports Debian no se aplican a wheels PyPI.

| Entrada | SHA-256 |
|---|---|
| report: trivy-high-critical.json | `6dae32d8a5db469e59757dbd7ecc6e770829f014492e9a1c8fb41391f733d07d` |
| sbom: sbom.cdx.json | `e251b47e132f05a5f0f827d6d1fd2503b388e4f16416e7beb698e8f8286c2239` |
| dpkg: baseline-dpkg.tsv | `2c2e8f2ae4a6c69887fc8bfb02bb1b4a91f4896cbb8ab8587c3298244072203a` |
| debian: debian-tracker-filtered.json | `b59164a775944a1fb426f4291891fd55c472f63308cb8d04277e8d46b23e44f4` |
| advisories: python-advisories.json | `c52b8599e8a2be1ab48c28783b121ea1222df61d24a4b72973641d7ebc271cc7` |
| pypi: python-pypi-metadata.json | `141cbe514f490665b5a54b64824d6c41d36ce90a068e2ff1db7f9f5882085edd` |

Artefactos detallados: `.ci-local/sec01-06e7d342/diagnosis/matrix/security-matrix.json` y `security-matrix.csv`; caches oficiales `debian-tracker-filtered.json`, `python-advisories.json`, `python-pypi-metadata.json`. No contienen datos editoriales ni credenciales.

```powershell
py -3.11 -B scripts/build_security_matrix.py `
  --report .ci-local/ci01-ba2ee8bc/trivy-high-critical.json `
  --sbom .ci-local/ci01-ba2ee8bc/sbom.cdx.json `
  --dpkg .ci-local/sec01-06e7d342/baseline-dpkg.tsv `
  --debian .ci-local/sec01-06e7d342/diagnosis/debian-tracker-filtered.json `
  --advisories .ci-local/sec01-06e7d342/diagnosis/python-advisories.json `
  --pypi .ci-local/sec01-06e7d342/diagnosis/python-pypi-metadata.json `
  --output-dir <directorio-nuevo> --markdown <archivo-nuevo.md>
```

El generador es stdlib/offline, exige exactamente 234 filas y 60 CVEs para esta línea base y rechaza sobreescribir salidas existentes. La API pública se consulta por separado; no hay consultas pagadas ni uso de la instalación activa.

## Decisiones mínimas antes de implementar

- **Libxml2 bloqueante:** ocho CVEs siguen abiertos en trixie; instalada y disponible `2.12.7+dfsg+really2.9.14-2.1+deb13u3`. La cadena observada es `ffmpeg → libavformat61 → libxml2`. Los fixes de forky/sid no corrigen automáticamente Debian 13. No se propone sustituir librerías de otra distribución.
- **OS:** de los 54 CVEs del sistema, 52 permanecen abiertos en trixie. Solo los dos de zlib publican aquí una versión corregida para la misma suite: `1:1.3.dfsg+really1.3.1-1+deb13u1`; requiere confirmar APT del snapshot y probar un parche dirigido. No implica cerrar los otros 226 hallazgos OS.
- **PyPI:** para cerrar los seis hallazgos del conjunto, mínimos publicados `python-multipart>=0.0.30` y `Starlette>=1.3.1`. FastAPI 0.115.12 exige `starlette>=0.40.0,<0.47.0`: no cabe forzar Starlette nueva bajo ese pin. El coordinador debe resolver y justificar un FastAPI compatible conservando transitivas no afectadas cuando sea posible.
- No se declara ningún falso positivo, VEX, allowlist o excepción por alcance Linux. Una condición de explotación específica se documenta y se prueba; no borra el finding ni abre el gate.

## Selección posterior de candidato: no cambia el baseline

El mínimo `python-multipart>=0.0.30` de los tres CVEs anteriores no equivale a recomendar instalar exactamente 0.0.30. La revisión posterior encontró [GHSA-v9pg-7xvm-68hf / CVE-2026-53540](https://github.com/Kludex/python-multipart/security/advisories/GHSA-v9pg-7xvm-68hf): la página del proyecto lo clasifica LOW (CVSS 3.7), declara afectados `<0.0.31` y corregido `0.0.31`. No se añade a los 234 hallazgos/60 CVEs de la captura HIGH/CRITICAL ni se afirma que solo se introdujo en 0.0.30.

El candidato deliberado pasa a `python-multipart==0.0.31` ([release y wheel oficial](https://pypi.org/project/python-multipart/0.0.31/), SHA-256 `8408153d68a9773291fc1da39a8b85a50044bddbabd2dd72e9229776b7b15e28`), sujeto a resolución y regresiones. Como regresión adicional, una llamada aislada a parse_form con Content-Length negativo debe rechazar antes de leer el stream; no se ejecuta contra el servicio activo. No se declara un VEX por las condiciones de explotación.

El coordinador verificó la frontera de compatibilidad FastAPI 0.132.1 (`starlette<1.0.0`) → [0.133.0](https://pypi.org/pypi/fastapi/0.133.0/json) (`starlette>=0.40.0`), que permite el candidato Starlette 1.3.1. Esa comprobación de frontera no es una auditoría exhaustiva de todas las releases históricas. El conjunto propuesto se valida con constraints de las transitivas no afectadas; no se sustituye por las últimas versiones sin necesidad.

## Regresiones exigidas

- **OS:** Verificar candidato/paquete fuente/versión con APT y dpkg de la misma suite; rebuild por digest; pip check, imports nativos, suite completa sin omisiones, SBOM y reescaneo de la misma imagen.
- **MEDIA:** Además de OS: checks reales media/presentation/branding; FFmpeg/ffprobe, audio AAC/WAV/VAD, MP4/subtítulos/plantillas, entrega ZIP y recuperación con fixtures sintéticos.
- **API:** Resolver FastAPI/Starlette/multipart sin forzar incompatibilidades; pip check; API/editorial/entregas, carga multipart, FileResponse/Range y suite completa; reescaneo del mismo artefacto.

Las pruebas de esta matriz son análisis de evidencia y contrastes oficiales. Los tests nuevos de remediación, el nuevo build/SBOM/scan y el navegador permanecen pendientes de ejecución del candidato. Las respuestas ASR/IA de la suite siguen siendo fixtures identificados.

## SAST y herramientas CI

Al iniciar SEC-01 no se encontró SAST de Python en las fuentes inspeccionadas: Gitleaks detecta secretos y Trivy dependencias, no sustituyen un analizador del código. Se propone Bandit **1.9.4**, wheel SHA-256 `f89ffa663767f5a0585ea075f01020207e966a9c0f2b9ef56a57c7963a3f6f8e`, publicado mediante Trusted Publishing en [PyPI](https://pypi.org/project/bandit/1.9.4/) y [release PyCQA](https://github.com/PyCQA/bandit/releases/tag/1.9.4).

Ejecutar en un stage/entorno de herramientas separado, hash-lock transitivo propio, inventario/SBOM/scan propios, snapshot fuente readonly y `--network none`. No instalar Bandit en el runtime app ni ocultar sus paquetes de los scans de herramientas. CLI [oficial](https://bandit.readthedocs.io/en/latest/man/bandit.html):

```text
python -m bandit -r /source/app /source/scripts --severity-level all --confidence-level all --ignore-nosec --format json --output /reports/bandit.json
```

Sin skips, baseline de supresión, exclusiones generales ni `--exit-zero`; inicialmente todos los hallazgos bloquean. Los hallazgos legacy exigen revisión y, si requieren cambios de lógica, una propuesta separada. La instalación/ejecución e integración del SAST corresponden al coordinador y no se presentan como ejecutadas por esta matriz.

## Resumen de los 60 CVEs

| CVE | Hallazgos | Source package/distribución | Estado oficial | Fixed oficial aplicable |
|---|---:|---|---|---|
| [CVE-2025-62727](https://github.com/Kludex/starlette/security/advisories/GHSA-7f5h-v6xp-fcq8) | 1 | starlette / PyPI | patched_release_published | 0.49.1 |
| [CVE-2025-69720](https://security-tracker.debian.org/tracker/CVE-2025-69720) | 4 | ncurses / trixie | open | ausente |
| [CVE-2026-109089](https://security-tracker.debian.org/tracker/CVE-2026-109089) | 1 | libxi / trixie | open | ausente |
| [CVE-2026-109090](https://security-tracker.debian.org/tracker/CVE-2026-109090) | 1 | libxi / trixie | open | ausente |
| [CVE-2026-113351](https://security-tracker.debian.org/tracker/CVE-2026-113351) | 1 | expat / trixie | open | ausente |
| [CVE-2026-115506](https://security-tracker.debian.org/tracker/CVE-2026-115506) | 1 | expat / trixie | open | ausente |
| [CVE-2026-117610](https://security-tracker.debian.org/tracker/CVE-2026-117610) | 1 | expat / trixie | open | ausente |
| [CVE-2026-118370](https://security-tracker.debian.org/tracker/CVE-2026-118370) | 1 | expat / trixie | open | ausente |
| [CVE-2026-119373](https://security-tracker.debian.org/tracker/CVE-2026-119373) | 1 | sqlite3 / trixie | open | ausente |
| [CVE-2026-119374](https://security-tracker.debian.org/tracker/CVE-2026-119374) | 1 | sqlite3 / trixie | open | ausente |
| [CVE-2026-119379](https://security-tracker.debian.org/tracker/CVE-2026-119379) | 1 | sqlite3 / trixie | open | ausente |
| [CVE-2026-16554](https://security-tracker.debian.org/tracker/CVE-2026-16554) | 1 | cjson / trixie | open | ausente |
| [CVE-2026-16742](https://security-tracker.debian.org/tracker/CVE-2026-16742) | 2 | systemd / trixie | open | ausente |
| [CVE-2026-24486](https://github.com/Kludex/python-multipart/security/advisories/GHSA-wp53-j4wj-2cfg) | 1 | python-multipart / PyPI | patched_release_published | 0.0.22 |
| [CVE-2026-29036](https://security-tracker.debian.org/tracker/CVE-2026-29036) | 1 | cjson / trixie | open | ausente |
| [CVE-2026-36849](https://security-tracker.debian.org/tracker/CVE-2026-36849) | 1 | tiff / trixie | open | ausente |
| [CVE-2026-37555](https://security-tracker.debian.org/tracker/CVE-2026-37555) | 1 | libsndfile / trixie | open | ausente |
| [CVE-2026-42561](https://github.com/Kludex/python-multipart/security/advisories/GHSA-pp6c-gr5w-3c5g) | 1 | python-multipart / PyPI | patched_release_published | 0.0.27 |
| [CVE-2026-48818](https://github.com/Kludex/starlette/security/advisories/GHSA-wqp7-x3pw-xc5r) | 1 | starlette / PyPI | patched_release_published | 1.1.0 |
| [CVE-2026-52490](https://security-tracker.debian.org/tracker/CVE-2026-52490) | 1 | tiff / trixie | open | ausente |
| [CVE-2026-53539](https://github.com/Kludex/python-multipart/security/advisories/GHSA-5rvq-cxj2-64vf) | 1 | python-multipart / PyPI | patched_release_published | 0.0.30 |
| [CVE-2026-54283](https://github.com/Kludex/starlette/security/advisories/GHSA-82w8-qh3p-5jfq) | 1 | starlette / PyPI | patched_release_published | 1.3.1 |
| [CVE-2026-54369](https://security-tracker.debian.org/tracker/CVE-2026-54369) | 1 | acl / trixie | open | ausente |
| [CVE-2026-58049](https://security-tracker.debian.org/tracker/CVE-2026-58049) | 9 | ffmpeg / trixie | open | ausente |
| [CVE-2026-64830](https://security-tracker.debian.org/tracker/CVE-2026-64830) | 9 | ffmpeg / trixie | open | ausente |
| [CVE-2026-64832](https://security-tracker.debian.org/tracker/CVE-2026-64832) | 9 | ffmpeg / trixie | open | ausente |
| [CVE-2026-64833](https://security-tracker.debian.org/tracker/CVE-2026-64833) | 9 | ffmpeg / trixie | open | ausente |
| [CVE-2026-64834](https://security-tracker.debian.org/tracker/CVE-2026-64834) | 9 | ffmpeg / trixie | open | ausente |
| [CVE-2026-64835](https://security-tracker.debian.org/tracker/CVE-2026-64835) | 9 | ffmpeg / trixie | open | ausente |
| [CVE-2026-66036](https://security-tracker.debian.org/tracker/CVE-2026-66036) | 9 | ffmpeg / trixie | open | ausente |
| [CVE-2026-66039](https://security-tracker.debian.org/tracker/CVE-2026-66039) | 9 | ffmpeg / trixie | open | ausente |
| [CVE-2026-66040](https://security-tracker.debian.org/tracker/CVE-2026-66040) | 9 | ffmpeg / trixie | open | ausente |
| [CVE-2026-66041](https://security-tracker.debian.org/tracker/CVE-2026-66041) | 9 | ffmpeg / trixie | open | ausente |
| [CVE-2026-6653](https://security-tracker.debian.org/tracker/CVE-2026-6653) | 1 | libxml2 / trixie | open | ausente |
| [CVE-2026-67215](https://security-tracker.debian.org/tracker/CVE-2026-67215) | 1 | cjson / trixie | open | ausente |
| [CVE-2026-67216](https://security-tracker.debian.org/tracker/CVE-2026-67216) | 1 | cjson / trixie | open | ausente |
| [CVE-2026-70628](https://security-tracker.debian.org/tracker/CVE-2026-70628) | 9 | ffmpeg / trixie | open | ausente |
| [CVE-2026-70632](https://security-tracker.debian.org/tracker/CVE-2026-70632) | 9 | ffmpeg / trixie | open | ausente |
| [CVE-2026-74860](https://security-tracker.debian.org/tracker/CVE-2026-74860) | 1 | libxml2 / trixie | open | ausente |
| [CVE-2026-75141](https://security-tracker.debian.org/tracker/CVE-2026-75141) | 9 | ffmpeg / trixie | open | ausente |
| [CVE-2026-75142](https://security-tracker.debian.org/tracker/CVE-2026-75142) | 9 | ffmpeg / trixie | open | ausente |
| [CVE-2026-75143](https://security-tracker.debian.org/tracker/CVE-2026-75143) | 9 | ffmpeg / trixie | open | ausente |
| [CVE-2026-75144](https://security-tracker.debian.org/tracker/CVE-2026-75144) | 9 | ffmpeg / trixie | open | ausente |
| [CVE-2026-75146](https://security-tracker.debian.org/tracker/CVE-2026-75146) | 9 | ffmpeg / trixie | open | ausente |
| [CVE-2026-76642](https://security-tracker.debian.org/tracker/CVE-2026-76642) | 9 | util-linux / trixie | open | ausente |
| [CVE-2026-76844](https://security-tracker.debian.org/tracker/CVE-2026-76844) | 1 | zlib / trixie | resolved | 1:1.3.dfsg+really1.3.1-1+deb13u1 |
| [CVE-2026-78408](https://security-tracker.debian.org/tracker/CVE-2026-78408) | 9 | util-linux / trixie | open | ausente |
| [CVE-2026-78409](https://security-tracker.debian.org/tracker/CVE-2026-78409) | 9 | util-linux / trixie | open | ausente |
| [CVE-2026-78410](https://security-tracker.debian.org/tracker/CVE-2026-78410) | 9 | util-linux / trixie | open | ausente |
| [CVE-2026-85091](https://security-tracker.debian.org/tracker/CVE-2026-85091) | 1 | zlib / trixie | resolved | 1:1.3.dfsg+really1.3.1-1+deb13u1 |
| [CVE-2026-86138](https://security-tracker.debian.org/tracker/CVE-2026-86138) | 1 | libxml2 / trixie | open | ausente |
| [CVE-2026-86139](https://security-tracker.debian.org/tracker/CVE-2026-86139) | 1 | libxml2 / trixie | open | ausente |
| [CVE-2026-86140](https://security-tracker.debian.org/tracker/CVE-2026-86140) | 1 | libxml2 / trixie | open | ausente |
| [CVE-2026-86142](https://security-tracker.debian.org/tracker/CVE-2026-86142) | 1 | libxml2 / trixie | open | ausente |
| [CVE-2026-86143](https://security-tracker.debian.org/tracker/CVE-2026-86143) | 1 | libxml2 / trixie | open | ausente |
| [CVE-2026-86144](https://security-tracker.debian.org/tracker/CVE-2026-86144) | 1 | libxml2 / trixie | open | ausente |
| [CVE-2026-87933](https://security-tracker.debian.org/tracker/CVE-2026-87933) | 1 | cjson / trixie | open | ausente |
| [CVE-2026-88806](https://security-tracker.debian.org/tracker/CVE-2026-88806) | 3 | libx11 / trixie | open | ausente |
| [CVE-2026-88807](https://security-tracker.debian.org/tracker/CVE-2026-88807) | 1 | libxrender / trixie | open | ausente |
| [CVE-2026-9538](https://security-tracker.debian.org/tracker/CVE-2026-9538) | 1 | perl / trixie | open | ausente |

## Detalle íntegro por CVE y hallazgo

En cada tabla, `SrcName crudo` conserva el campo del finding; la columna source/versión procede del inventario CI separado. `DataSource` incluye ID, nombre y URL completos en JSON; su ID se muestra aquí y no equivale a `SeveritySource`. Todas las filas conservan target, PURL, capa, evidencia introductora, CVSS/VendorSeverity observados y remediación pendiente en JSON.

### CVE-2025-62727 — starlette (1 hallazgos)

Fuente verificada: [GHSA-7f5h-v6xp-fcq8](https://github.com/Kludex/starlette/security/advisories/GHSA-7f5h-v6xp-fcq8); consulta `2026-11-10T01:23:34.6450823Z`. Estado: **patched_release_published**; fixed aplicable: **0.49.1**.

Corrección mínima: PyPI starlette>=0.49.1 para este CVE. Para cerrar los tres del paquete se requiere Starlette>=1.3.1 y FastAPI compatible; 0.115.12 exige Starlette<0.47. Resolver y fijar el bundle deliberadamente, sin --no-deps/override incompatible; aún no ejecutado.

Rango oficial afectado: `>= 0.39.0, <= 0.49.0`. Distribución instalada: PyPI; no usar las versiones corregidas de paquetes Debian.

| ID | Paquete binario @ instalada | Source @ versión | SrcName crudo | Severidad / SeveritySource | Status / DataSource.ID | FixedVersion crudo | Ámbito |
|---|---|---|---|---|---|---|---|
| F001 | starlette @ 0.46.2 | starlette @ 0.46.2 | ausente | HIGH / ghsa | fixed / ghsa | 0.49.1 | app |

Introductor y origen por fila:

- **F001:** requirements.txt → FastAPI 0.115.12 → starlette<0.47.0,>=0.40.0 → Starlette 0.46.2. Origen: Wheel PyPI en imagen CI; no paquete Debian. Evidencia: https://pypi.org/pypi/fastapi/0.115.12/json Requires-Dist; el SBOM no conserva esta arista Python. Regresiones: API.

Regresión específica: FileResponse/Range prefix/suffix/open, múltiples rangos/solapamiento, If-Range y 416; verificar el cambio del parser sin presentar esos casos como benchmark DoS.

### CVE-2025-69720 — ncurses (4 hallazgos)

Fuente verificada: [Debian Security Tracker](https://security-tracker.debian.org/tracker/CVE-2025-69720); consulta `2026-11-10T01:23:38.2797542Z`. Estado: **open**; fixed aplicable: **ausente**.

Corrección mínima: Bloqueado: Debian trixie mantiene ncurses/CVE-2025-69720 abierto y no publica fixed_version para esta suite. Ningún pin corregido respaldado; no usar sid/forky ni declarar remediado por actualizar el snapshot.

Repositorios de trixie observados: {"trixie": "6.5+20250216-2"}.

| ID | Paquete binario @ instalada | Source @ versión | SrcName crudo | Severidad / SeveritySource | Status / DataSource.ID | FixedVersion crudo | Ámbito |
|---|---|---|---|---|---|---|---|
| F002 | libncursesw6 @ 6.5+20250216-2 | ncurses @ 6.5+20250216-2 | ausente | HIGH / nvd | affected / debian | ausente | sistema |
| F003 | libtinfo6 @ 6.5+20250216-2 | ncurses @ 6.5+20250216-2 | ausente | HIGH / nvd | affected / debian | ausente | sistema |
| F004 | ncurses-base @ 6.5+20250216-2 | ncurses @ 6.5+20250216-2 | ausente | HIGH / nvd | affected / debian | ausente | sistema |
| F005 | ncurses-bin @ 6.5+20250216-2 | ncurses @ 6.5+20250216-2 | ausente | HIGH / nvd | affected / debian | ausente | sistema |

Introductor y origen por fila:

- **F002:** APT CI explícito: ffmpeg → libavdevice61 → libcaca0 → libncursesw6. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F003:** APT CI explícito: ffmpeg → libavdevice61 → libcaca0 → libtinfo6. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F004:** Base Python/Debian (inferencia por capa); introductor concreto no identificado. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DiffID observado, sin inventar una arista de dependencia. Regresiones: OS.
- **F005:** Base Python/Debian (inferencia por capa); introductor concreto no identificado. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DiffID observado, sin inventar una arista de dependencia. Regresiones: OS.

### CVE-2026-109089 — libxi (1 hallazgos)

Fuente verificada: [Debian Security Tracker](https://security-tracker.debian.org/tracker/CVE-2026-109089); consulta `2026-11-10T01:23:38.2797542Z`. Estado: **open**; fixed aplicable: **ausente**.

Corrección mínima: Bloqueado: Debian trixie mantiene libxi/CVE-2026-109089 abierto y no publica fixed_version para esta suite. Ningún pin corregido respaldado; no usar sid/forky ni declarar remediado por actualizar el snapshot.

Repositorios de trixie observados: {"trixie": "2:1.8.2-1"}.

| ID | Paquete binario @ instalada | Source @ versión | SrcName crudo | Severidad / SeveritySource | Status / DataSource.ID | FixedVersion crudo | Ámbito |
|---|---|---|---|---|---|---|---|
| F006 | libxi6 @ 2:1.8.2-1 | libxi @ 2:1.8.2-1 | ausente | HIGH / ausente | affected / debian | ausente | sistema |

Introductor y origen por fila:

- **F006:** APT CI explícito: ffmpeg → libsdl2-2.0-0 → libxi6. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.

### CVE-2026-109090 — libxi (1 hallazgos)

Fuente verificada: [Debian Security Tracker](https://security-tracker.debian.org/tracker/CVE-2026-109090); consulta `2026-11-10T01:23:38.2797542Z`. Estado: **open**; fixed aplicable: **ausente**.

Corrección mínima: Bloqueado: Debian trixie mantiene libxi/CVE-2026-109090 abierto y no publica fixed_version para esta suite. Ningún pin corregido respaldado; no usar sid/forky ni declarar remediado por actualizar el snapshot.

Repositorios de trixie observados: {"trixie": "2:1.8.2-1"}.

| ID | Paquete binario @ instalada | Source @ versión | SrcName crudo | Severidad / SeveritySource | Status / DataSource.ID | FixedVersion crudo | Ámbito |
|---|---|---|---|---|---|---|---|
| F007 | libxi6 @ 2:1.8.2-1 | libxi @ 2:1.8.2-1 | ausente | HIGH / ausente | affected / debian | ausente | sistema |

Introductor y origen por fila:

- **F007:** APT CI explícito: ffmpeg → libsdl2-2.0-0 → libxi6. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.

### CVE-2026-113351 — expat (1 hallazgos)

Fuente verificada: [Debian Security Tracker](https://security-tracker.debian.org/tracker/CVE-2026-113351); consulta `2026-11-10T01:23:38.2797542Z`. Estado: **open**; fixed aplicable: **ausente**.

Corrección mínima: Bloqueado: Debian trixie mantiene expat/CVE-2026-113351 abierto y no publica fixed_version para esta suite. Ningún pin corregido respaldado; no usar sid/forky ni declarar remediado por actualizar el snapshot.

Repositorios de trixie observados: {"trixie": "2.8.3-1~deb13u1", "trixie-security": "2.9.0-1~deb13u1"}.

| ID | Paquete binario @ instalada | Source @ versión | SrcName crudo | Severidad / SeveritySource | Status / DataSource.ID | FixedVersion crudo | Ámbito |
|---|---|---|---|---|---|---|---|
| F008 | libexpat1 @ 2.9.0-1~deb13u1 | expat @ 2.9.0-1~deb13u1 | ausente | HIGH / nvd | affected / debian | ausente | sistema |

Introductor y origen por fila:

- **F008:** APT CI explícito: ffmpeg → libavfilter10 → libfontconfig1 → libexpat1. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.

### CVE-2026-115506 — expat (1 hallazgos)

Fuente verificada: [Debian Security Tracker](https://security-tracker.debian.org/tracker/CVE-2026-115506); consulta `2026-11-10T01:23:38.2797542Z`. Estado: **open**; fixed aplicable: **ausente**.

Corrección mínima: Bloqueado: Debian trixie mantiene expat/CVE-2026-115506 abierto y no publica fixed_version para esta suite. Ningún pin corregido respaldado; no usar sid/forky ni declarar remediado por actualizar el snapshot.

Repositorios de trixie observados: {"trixie": "2.8.3-1~deb13u1", "trixie-security": "2.9.0-1~deb13u1"}.

| ID | Paquete binario @ instalada | Source @ versión | SrcName crudo | Severidad / SeveritySource | Status / DataSource.ID | FixedVersion crudo | Ámbito |
|---|---|---|---|---|---|---|---|
| F009 | libexpat1 @ 2.9.0-1~deb13u1 | expat @ 2.9.0-1~deb13u1 | ausente | HIGH / ausente | affected / debian | ausente | sistema |

Introductor y origen por fila:

- **F009:** APT CI explícito: ffmpeg → libavfilter10 → libfontconfig1 → libexpat1. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.

### CVE-2026-117610 — expat (1 hallazgos)

Fuente verificada: [Debian Security Tracker](https://security-tracker.debian.org/tracker/CVE-2026-117610); consulta `2026-11-10T01:23:38.2797542Z`. Estado: **open**; fixed aplicable: **ausente**.

Corrección mínima: Bloqueado: Debian trixie mantiene expat/CVE-2026-117610 abierto y no publica fixed_version para esta suite. Ningún pin corregido respaldado; no usar sid/forky ni declarar remediado por actualizar el snapshot.

Repositorios de trixie observados: {"trixie": "2.8.3-1~deb13u1", "trixie-security": "2.9.0-1~deb13u1"}.

| ID | Paquete binario @ instalada | Source @ versión | SrcName crudo | Severidad / SeveritySource | Status / DataSource.ID | FixedVersion crudo | Ámbito |
|---|---|---|---|---|---|---|---|
| F010 | libexpat1 @ 2.9.0-1~deb13u1 | expat @ 2.9.0-1~deb13u1 | ausente | HIGH / nvd | affected / debian | ausente | sistema |

Introductor y origen por fila:

- **F010:** APT CI explícito: ffmpeg → libavfilter10 → libfontconfig1 → libexpat1. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.

### CVE-2026-118370 — expat (1 hallazgos)

Fuente verificada: [Debian Security Tracker](https://security-tracker.debian.org/tracker/CVE-2026-118370); consulta `2026-11-10T01:23:38.2797542Z`. Estado: **open**; fixed aplicable: **ausente**.

Corrección mínima: Bloqueado: Debian trixie mantiene expat/CVE-2026-118370 abierto y no publica fixed_version para esta suite. Ningún pin corregido respaldado; no usar sid/forky ni declarar remediado por actualizar el snapshot.

Repositorios de trixie observados: {"trixie": "2.8.3-1~deb13u1", "trixie-security": "2.9.0-1~deb13u1"}.

| ID | Paquete binario @ instalada | Source @ versión | SrcName crudo | Severidad / SeveritySource | Status / DataSource.ID | FixedVersion crudo | Ámbito |
|---|---|---|---|---|---|---|---|
| F011 | libexpat1 @ 2.9.0-1~deb13u1 | expat @ 2.9.0-1~deb13u1 | ausente | HIGH / nvd | affected / debian | ausente | sistema |

Introductor y origen por fila:

- **F011:** APT CI explícito: ffmpeg → libavfilter10 → libfontconfig1 → libexpat1. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.

### CVE-2026-119373 — sqlite3 (1 hallazgos)

Fuente verificada: [Debian Security Tracker](https://security-tracker.debian.org/tracker/CVE-2026-119373); consulta `2026-11-10T01:23:38.2797542Z`. Estado: **open**; fixed aplicable: **ausente**.

Corrección mínima: Bloqueado: Debian trixie mantiene sqlite3/CVE-2026-119373 abierto y no publica fixed_version para esta suite. Ningún pin corregido respaldado; no usar sid/forky ni declarar remediado por actualizar el snapshot.

Repositorios de trixie observados: {"trixie": "3.46.1-7+deb13u2"}.

| ID | Paquete binario @ instalada | Source @ versión | SrcName crudo | Severidad / SeveritySource | Status / DataSource.ID | FixedVersion crudo | Ámbito |
|---|---|---|---|---|---|---|---|
| F012 | libsqlite3-0 @ 3.46.1-7+deb13u2 | sqlite3 @ 3.46.1-7+deb13u2 | ausente | HIGH / ausente | affected / debian | ausente | sistema |

Introductor y origen por fila:

- **F012:** Base Python/Debian (inferencia por capa); introductor concreto no identificado. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DiffID observado, sin inventar una arista de dependencia. Regresiones: OS.

### CVE-2026-119374 — sqlite3 (1 hallazgos)

Fuente verificada: [Debian Security Tracker](https://security-tracker.debian.org/tracker/CVE-2026-119374); consulta `2026-11-10T01:23:38.2797542Z`. Estado: **open**; fixed aplicable: **ausente**.

Corrección mínima: Bloqueado: Debian trixie mantiene sqlite3/CVE-2026-119374 abierto y no publica fixed_version para esta suite. Ningún pin corregido respaldado; no usar sid/forky ni declarar remediado por actualizar el snapshot.

Repositorios de trixie observados: {"trixie": "3.46.1-7+deb13u2"}.

| ID | Paquete binario @ instalada | Source @ versión | SrcName crudo | Severidad / SeveritySource | Status / DataSource.ID | FixedVersion crudo | Ámbito |
|---|---|---|---|---|---|---|---|
| F013 | libsqlite3-0 @ 3.46.1-7+deb13u2 | sqlite3 @ 3.46.1-7+deb13u2 | ausente | HIGH / ausente | affected / debian | ausente | sistema |

Introductor y origen por fila:

- **F013:** Base Python/Debian (inferencia por capa); introductor concreto no identificado. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DiffID observado, sin inventar una arista de dependencia. Regresiones: OS.

### CVE-2026-119379 — sqlite3 (1 hallazgos)

Fuente verificada: [Debian Security Tracker](https://security-tracker.debian.org/tracker/CVE-2026-119379); consulta `2026-11-10T01:23:38.2797542Z`. Estado: **open**; fixed aplicable: **ausente**.

Corrección mínima: Bloqueado: Debian trixie mantiene sqlite3/CVE-2026-119379 abierto y no publica fixed_version para esta suite. Ningún pin corregido respaldado; no usar sid/forky ni declarar remediado por actualizar el snapshot.

Repositorios de trixie observados: {"trixie": "3.46.1-7+deb13u2"}.

| ID | Paquete binario @ instalada | Source @ versión | SrcName crudo | Severidad / SeveritySource | Status / DataSource.ID | FixedVersion crudo | Ámbito |
|---|---|---|---|---|---|---|---|
| F014 | libsqlite3-0 @ 3.46.1-7+deb13u2 | sqlite3 @ 3.46.1-7+deb13u2 | ausente | HIGH / ausente | affected / debian | ausente | sistema |

Introductor y origen por fila:

- **F014:** Base Python/Debian (inferencia por capa); introductor concreto no identificado. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DiffID observado, sin inventar una arista de dependencia. Regresiones: OS.

### CVE-2026-16554 — cjson (1 hallazgos)

Fuente verificada: [Debian Security Tracker](https://security-tracker.debian.org/tracker/CVE-2026-16554); consulta `2026-11-10T01:23:38.2797542Z`. Estado: **open**; fixed aplicable: **ausente**.

Corrección mínima: Bloqueado: Debian trixie mantiene cjson/CVE-2026-16554 abierto y no publica fixed_version para esta suite. Ningún pin corregido respaldado; no usar sid/forky ni declarar remediado por actualizar el snapshot.

Repositorios de trixie observados: {"trixie": "1.7.18-3.1+deb13u1", "trixie-security": "1.7.18-3.1+deb13u1"}.

| ID | Paquete binario @ instalada | Source @ versión | SrcName crudo | Severidad / SeveritySource | Status / DataSource.ID | FixedVersion crudo | Ámbito |
|---|---|---|---|---|---|---|---|
| F015 | libcjson1 @ 1.7.18-3.1+deb13u1 | cjson @ 1.7.18-3.1+deb13u1 | ausente | HIGH / nvd | affected / debian | ausente | sistema |

Introductor y origen por fila:

- **F015:** APT CI explícito: ffmpeg → libavformat61 → librist4 → libcjson1. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.

### CVE-2026-16742 — systemd (2 hallazgos)

Fuente verificada: [Debian Security Tracker](https://security-tracker.debian.org/tracker/CVE-2026-16742); consulta `2026-11-10T01:23:38.2797542Z`. Estado: **open**; fixed aplicable: **ausente**.

Corrección mínima: Bloqueado: Debian trixie mantiene systemd/CVE-2026-16742 abierto y no publica fixed_version para esta suite. Ningún pin corregido respaldado; no usar sid/forky ni declarar remediado por actualizar el snapshot.

Repositorios de trixie observados: {"trixie": "257.13-1~deb13u1"}.

| ID | Paquete binario @ instalada | Source @ versión | SrcName crudo | Severidad / SeveritySource | Status / DataSource.ID | FixedVersion crudo | Ámbito |
|---|---|---|---|---|---|---|---|
| F016 | libsystemd0 @ 257.13-1~deb13u1 | systemd @ 257.13-1~deb13u1 | ausente | HIGH / ausente | affected / debian | ausente | sistema |
| F017 | libudev1 @ 257.13-1~deb13u1 | systemd @ 257.13-1~deb13u1 | ausente | HIGH / ausente | affected / debian | ausente | sistema |

Introductor y origen por fila:

- **F016:** APT CI explícito: ffmpeg → libavdevice61 → libpulse0 → libsystemd0. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F017:** APT CI explícito: ffmpeg → libavdevice61 → libdc1394-25 → libusb-1.0-0 → libudev1. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.

### CVE-2026-24486 — python-multipart (1 hallazgos)

Fuente verificada: [GHSA-wp53-j4wj-2cfg](https://github.com/Kludex/python-multipart/security/advisories/GHSA-wp53-j4wj-2cfg); consulta `2026-11-10T01:23:33.2284861Z`. Estado: **patched_release_published**; fixed aplicable: **0.0.22**.

Corrección mínima: PyPI python-multipart>=0.0.22 para este CVE. Para cerrar los tres del paquete se requiere python-multipart>=0.0.30. Resolver y fijar el bundle deliberadamente, sin --no-deps/override incompatible; aún no ejecutado.

Rango oficial afectado: `< 0.0.22`. Distribución instalada: PyPI; no usar las versiones corregidas de paquetes Debian.

| ID | Paquete binario @ instalada | Source @ versión | SrcName crudo | Severidad / SeveritySource | Status / DataSource.ID | FixedVersion crudo | Ámbito |
|---|---|---|---|---|---|---|---|
| F018 | python-multipart @ 0.0.20 | python-multipart @ 0.0.20 | ausente | HIGH / ghsa | fixed / ghsa | 0.0.22 | app |

Introductor y origen por fila:

- **F018:** requirements.txt → python-multipart==0.0.20 (directa). Origen: Wheel PyPI en imagen CI; no paquete Debian. Evidencia: Pin directo en el baseline de fuentes. Regresiones: API.

Regresión específica: Filenames absolutos/traversal con configuración de upload no predeterminada en directorio temporal; ninguna escritura fuera del destino; conservar upload normal.

### CVE-2026-29036 — cjson (1 hallazgos)

Fuente verificada: [Debian Security Tracker](https://security-tracker.debian.org/tracker/CVE-2026-29036); consulta `2026-11-10T01:23:38.2797542Z`. Estado: **open**; fixed aplicable: **ausente**.

Corrección mínima: Bloqueado: Debian trixie mantiene cjson/CVE-2026-29036 abierto y no publica fixed_version para esta suite. Ningún pin corregido respaldado; no usar sid/forky ni declarar remediado por actualizar el snapshot.

Repositorios de trixie observados: {"trixie": "1.7.18-3.1+deb13u1", "trixie-security": "1.7.18-3.1+deb13u1"}.

| ID | Paquete binario @ instalada | Source @ versión | SrcName crudo | Severidad / SeveritySource | Status / DataSource.ID | FixedVersion crudo | Ámbito |
|---|---|---|---|---|---|---|---|
| F019 | libcjson1 @ 1.7.18-3.1+deb13u1 | cjson @ 1.7.18-3.1+deb13u1 | ausente | HIGH / ausente | affected / debian | ausente | sistema |

Introductor y origen por fila:

- **F019:** APT CI explícito: ffmpeg → libavformat61 → librist4 → libcjson1. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.

### CVE-2026-36849 — tiff (1 hallazgos)

Fuente verificada: [Debian Security Tracker](https://security-tracker.debian.org/tracker/CVE-2026-36849); consulta `2026-11-10T01:23:38.2797542Z`. Estado: **open**; fixed aplicable: **ausente**.

Corrección mínima: Bloqueado: Debian trixie mantiene tiff/CVE-2026-36849 abierto y no publica fixed_version para esta suite. Ningún pin corregido respaldado; no usar sid/forky ni declarar remediado por actualizar el snapshot.

Repositorios de trixie observados: {"trixie": "4.7.0-3+deb13u3", "trixie-security": "4.7.0-3+deb13u3"}.

| ID | Paquete binario @ instalada | Source @ versión | SrcName crudo | Severidad / SeveritySource | Status / DataSource.ID | FixedVersion crudo | Ámbito |
|---|---|---|---|---|---|---|---|
| F020 | libtiff6 @ 4.7.0-3+deb13u3 | tiff @ 4.7.0-3+deb13u3 | ausente | HIGH / ausente | will_not_fix / debian | ausente | sistema |

Introductor y origen por fila:

- **F020:** APT CI explícito: ffmpeg → libavcodec61 → librsvg2-2 → libgdk-pixbuf-2.0-0 → libtiff6. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.

### CVE-2026-37555 — libsndfile (1 hallazgos)

Fuente verificada: [Debian Security Tracker](https://security-tracker.debian.org/tracker/CVE-2026-37555); consulta `2026-11-10T01:23:38.2797542Z`. Estado: **open**; fixed aplicable: **ausente**.

Corrección mínima: Bloqueado: Debian trixie mantiene libsndfile/CVE-2026-37555 abierto y no publica fixed_version para esta suite. Ningún pin corregido respaldado; no usar sid/forky ni declarar remediado por actualizar el snapshot.

Repositorios de trixie observados: {"trixie": "1.2.2-2+deb13u1"}.

| ID | Paquete binario @ instalada | Source @ versión | SrcName crudo | Severidad / SeveritySource | Status / DataSource.ID | FixedVersion crudo | Ámbito |
|---|---|---|---|---|---|---|---|
| F021 | libsndfile1 @ 1.2.2-2+deb13u1 | libsndfile @ 1.2.2-2+deb13u1 | ausente | HIGH / ausente | affected / debian | ausente | sistema |

Introductor y origen por fila:

- **F021:** APT CI explícito: ffmpeg → libavdevice61 → libpulse0 → libsndfile1. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.

### CVE-2026-42561 — python-multipart (1 hallazgos)

Fuente verificada: [GHSA-pp6c-gr5w-3c5g](https://github.com/Kludex/python-multipart/security/advisories/GHSA-pp6c-gr5w-3c5g); consulta `2026-11-10T01:23:33.7910311Z`. Estado: **patched_release_published**; fixed aplicable: **0.0.27**.

Corrección mínima: PyPI python-multipart>=0.0.27 para este CVE. Para cerrar los tres del paquete se requiere python-multipart>=0.0.30. Resolver y fijar el bundle deliberadamente, sin --no-deps/override incompatible; aún no ejecutado.

Rango oficial afectado: `< 0.0.27`. Distribución instalada: PyPI; no usar las versiones corregidas de paquetes Debian.

| ID | Paquete binario @ instalada | Source @ versión | SrcName crudo | Severidad / SeveritySource | Status / DataSource.ID | FixedVersion crudo | Ámbito |
|---|---|---|---|---|---|---|---|
| F022 | python-multipart @ 0.0.20 | python-multipart @ 0.0.20 | ausente | HIGH / ghsa | fixed / ghsa | 0.0.27 | app |

Introductor y origen por fila:

- **F022:** requirements.txt → python-multipart==0.0.20 (directa). Origen: Wheel PyPI en imagen CI; no paquete Debian. Evidencia: Pin directo en el baseline de fuentes. Regresiones: API.

Regresión específica: Part headers excesivos/repetidos y header individual sobredimensionado; rechazo acotado y uploads válidos preservados, sin ejecutar cargas contra el servicio activo.

### CVE-2026-48818 — starlette (1 hallazgos)

Fuente verificada: [GHSA-wqp7-x3pw-xc5r](https://github.com/Kludex/starlette/security/advisories/GHSA-wqp7-x3pw-xc5r); consulta `2026-11-10T01:23:35.1157615Z`. Estado: **patched_release_published**; fixed aplicable: **1.1.0**.

Corrección mínima: PyPI starlette>=1.1.0 para este CVE. Para cerrar los tres del paquete se requiere Starlette>=1.3.1 y FastAPI compatible; 0.115.12 exige Starlette<0.47. Resolver y fijar el bundle deliberadamente, sin --no-deps/override incompatible; aún no ejecutado.

Rango oficial afectado: `< 1.1.0`. Distribución instalada: PyPI; no usar las versiones corregidas de paquetes Debian.

| ID | Paquete binario @ instalada | Source @ versión | SrcName crudo | Severidad / SeveritySource | Status / DataSource.ID | FixedVersion crudo | Ámbito |
|---|---|---|---|---|---|---|---|
| F023 | starlette @ 0.46.2 | starlette @ 0.46.2 | ausente | HIGH / ghsa | fixed / ghsa | 1.1.0 | app |

Introductor y origen por fila:

- **F023:** requirements.txt → FastAPI 0.115.12 → starlette<0.47.0,>=0.40.0 → Starlette 0.46.2. Origen: Wheel PyPI en imagen CI; no paquete Debian. Evidencia: https://pypi.org/pypi/fastapi/0.115.12/json Requires-Dist; el SBOM no conserva esta arista Python. Regresiones: API.

Regresión específica: StaticFiles rechaza UNC/rutas absolutas antes de resolver rutas remotas; validar Windows mediante fixture aislado sin red/SMB. El finding no se elimina por usar Linux.

### CVE-2026-52490 — tiff (1 hallazgos)

Fuente verificada: [Debian Security Tracker](https://security-tracker.debian.org/tracker/CVE-2026-52490); consulta `2026-11-10T01:23:38.2797542Z`. Estado: **open**; fixed aplicable: **ausente**.

Corrección mínima: Bloqueado: Debian trixie mantiene tiff/CVE-2026-52490 abierto y no publica fixed_version para esta suite. Ningún pin corregido respaldado; no usar sid/forky ni declarar remediado por actualizar el snapshot.

Repositorios de trixie observados: {"trixie": "4.7.0-3+deb13u3", "trixie-security": "4.7.0-3+deb13u3"}.

| ID | Paquete binario @ instalada | Source @ versión | SrcName crudo | Severidad / SeveritySource | Status / DataSource.ID | FixedVersion crudo | Ámbito |
|---|---|---|---|---|---|---|---|
| F024 | libtiff6 @ 4.7.0-3+deb13u3 | tiff @ 4.7.0-3+deb13u3 | ausente | HIGH / ausente | affected / debian | ausente | sistema |

Introductor y origen por fila:

- **F024:** APT CI explícito: ffmpeg → libavcodec61 → librsvg2-2 → libgdk-pixbuf-2.0-0 → libtiff6. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.

### CVE-2026-53539 — python-multipart (1 hallazgos)

Fuente verificada: [GHSA-5rvq-cxj2-64vf](https://github.com/Kludex/python-multipart/security/advisories/GHSA-5rvq-cxj2-64vf); consulta `2026-11-10T01:23:34.2227947Z`. Estado: **patched_release_published**; fixed aplicable: **0.0.30**.

Corrección mínima: PyPI python-multipart>=0.0.30 para este CVE. Para cerrar los tres del paquete se requiere python-multipart>=0.0.30. Resolver y fijar el bundle deliberadamente, sin --no-deps/override incompatible; aún no ejecutado.

Rango oficial afectado: `< 0.0.30`. Distribución instalada: PyPI; no usar las versiones corregidas de paquetes Debian.

| ID | Paquete binario @ instalada | Source @ versión | SrcName crudo | Severidad / SeveritySource | Status / DataSource.ID | FixedVersion crudo | Ámbito |
|---|---|---|---|---|---|---|---|
| F025 | python-multipart @ 0.0.20 | python-multipart @ 0.0.20 | ausente | HIGH / ghsa | fixed / ghsa | 0.0.30 | app |

Introductor y origen por fila:

- **F025:** requirements.txt → python-multipart==0.0.20 (directa). Origen: Wheel PyPI en imagen CI; no paquete Debian. Evidencia: Pin directo en el baseline de fuentes. Regresiones: API.

Regresión específica: Querystring con separadores ';' y '&', semántica del parser parcheado y límites; una prueba funcional no acredita complejidad temporal ni resistencia DoS.

### CVE-2026-54283 — starlette (1 hallazgos)

Fuente verificada: [GHSA-82w8-qh3p-5jfq](https://github.com/Kludex/starlette/security/advisories/GHSA-82w8-qh3p-5jfq); consulta `2026-11-10T01:23:35.5481480Z`. Estado: **patched_release_published**; fixed aplicable: **1.3.1**.

Corrección mínima: PyPI starlette>=1.3.1 para este CVE. Para cerrar los tres del paquete se requiere Starlette>=1.3.1 y FastAPI compatible; 0.115.12 exige Starlette<0.47. Resolver y fijar el bundle deliberadamente, sin --no-deps/override incompatible; aún no ejecutado.

Rango oficial afectado: `>= 0.4.1, < 1.3.1`. Distribución instalada: PyPI; no usar las versiones corregidas de paquetes Debian.

| ID | Paquete binario @ instalada | Source @ versión | SrcName crudo | Severidad / SeveritySource | Status / DataSource.ID | FixedVersion crudo | Ámbito |
|---|---|---|---|---|---|---|---|
| F026 | starlette @ 0.46.2 | starlette @ 0.46.2 | ausente | HIGH / ghsa | fixed / ghsa | 1.3.1 | app |

Introductor y origen por fila:

- **F026:** requirements.txt → FastAPI 0.115.12 → starlette<0.47.0,>=0.40.0 → Starlette 0.46.2. Origen: Wheel PyPI en imagen CI; no paquete Debian. Evidencia: https://pypi.org/pypi/fastapi/0.115.12/json Requires-Dist; el SBOM no conserva esta arista Python. Regresiones: API.

Regresión específica: Request.form urlencoded con max_fields=2 y tercer campo ->400; max_part_size cuenta nombre+valor raw: límite4 acepta a=123 y rechaza a=1234; multipart normal preservado.

### CVE-2026-54369 — acl (1 hallazgos)

Fuente verificada: [Debian Security Tracker](https://security-tracker.debian.org/tracker/CVE-2026-54369); consulta `2026-11-10T01:23:38.2797542Z`. Estado: **open**; fixed aplicable: **ausente**.

Corrección mínima: Bloqueado: Debian trixie mantiene acl/CVE-2026-54369 abierto y no publica fixed_version para esta suite. Ningún pin corregido respaldado; no usar sid/forky ni declarar remediado por actualizar el snapshot.

Repositorios de trixie observados: {"trixie": "2.3.2-2"}.

| ID | Paquete binario @ instalada | Source @ versión | SrcName crudo | Severidad / SeveritySource | Status / DataSource.ID | FixedVersion crudo | Ámbito |
|---|---|---|---|---|---|---|---|
| F027 | libacl1 @ 2.3.2-2+b1 | acl @ 2.3.2-2 | ausente | HIGH / ausente | affected / debian | ausente | sistema |

Introductor y origen por fila:

- **F027:** Base Python/Debian (inferencia por capa); introductor concreto no identificado. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DiffID observado, sin inventar una arista de dependencia. Regresiones: OS.

### CVE-2026-58049 — ffmpeg (9 hallazgos)

Fuente verificada: [Debian Security Tracker](https://security-tracker.debian.org/tracker/CVE-2026-58049); consulta `2026-11-10T01:23:38.2797542Z`. Estado: **open**; fixed aplicable: **ausente**.

Corrección mínima: Bloqueado: Debian trixie mantiene ffmpeg/CVE-2026-58049 abierto y no publica fixed_version para esta suite. Ningún pin corregido respaldado; no usar sid/forky ni declarar remediado por actualizar el snapshot.

Repositorios de trixie observados: {"trixie": "7:7.1.5-0+deb13u1", "trixie-security": "7:7.1.5-0+deb13u1"}.

| ID | Paquete binario @ instalada | Source @ versión | SrcName crudo | Severidad / SeveritySource | Status / DataSource.ID | FixedVersion crudo | Ámbito |
|---|---|---|---|---|---|---|---|
| F028 | ffmpeg @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |
| F029 | libavcodec61 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |
| F030 | libavdevice61 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |
| F031 | libavfilter10 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |
| F032 | libavformat61 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |
| F033 | libavutil59 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |
| F034 | libpostproc58 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |
| F035 | libswresample5 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |
| F036 | libswscale8 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |

Introductor y origen por fila:

- **F028:** APT CI explícito: ffmpeg. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F029:** APT CI explícito: ffmpeg → libavcodec61. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F030:** APT CI explícito: ffmpeg → libavdevice61. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F031:** APT CI explícito: ffmpeg → libavfilter10. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F032:** APT CI explícito: ffmpeg → libavformat61. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F033:** APT CI explícito: ffmpeg → libavutil59. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F034:** APT CI explícito: ffmpeg → libpostproc58. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F035:** APT CI explícito: ffmpeg → libswresample5. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F036:** APT CI explícito: ffmpeg → libswscale8. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.

### CVE-2026-64830 — ffmpeg (9 hallazgos)

Fuente verificada: [Debian Security Tracker](https://security-tracker.debian.org/tracker/CVE-2026-64830); consulta `2026-11-10T01:23:38.2797542Z`. Estado: **open**; fixed aplicable: **ausente**.

Corrección mínima: Bloqueado: Debian trixie mantiene ffmpeg/CVE-2026-64830 abierto y no publica fixed_version para esta suite. Ningún pin corregido respaldado; no usar sid/forky ni declarar remediado por actualizar el snapshot.

Repositorios de trixie observados: {"trixie": "7:7.1.5-0+deb13u1", "trixie-security": "7:7.1.5-0+deb13u1"}.

| ID | Paquete binario @ instalada | Source @ versión | SrcName crudo | Severidad / SeveritySource | Status / DataSource.ID | FixedVersion crudo | Ámbito |
|---|---|---|---|---|---|---|---|
| F037 | ffmpeg @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |
| F038 | libavcodec61 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |
| F039 | libavdevice61 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |
| F040 | libavfilter10 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |
| F041 | libavformat61 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |
| F042 | libavutil59 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |
| F043 | libpostproc58 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |
| F044 | libswresample5 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |
| F045 | libswscale8 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |

Introductor y origen por fila:

- **F037:** APT CI explícito: ffmpeg. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F038:** APT CI explícito: ffmpeg → libavcodec61. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F039:** APT CI explícito: ffmpeg → libavdevice61. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F040:** APT CI explícito: ffmpeg → libavfilter10. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F041:** APT CI explícito: ffmpeg → libavformat61. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F042:** APT CI explícito: ffmpeg → libavutil59. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F043:** APT CI explícito: ffmpeg → libpostproc58. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F044:** APT CI explícito: ffmpeg → libswresample5. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F045:** APT CI explícito: ffmpeg → libswscale8. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.

### CVE-2026-64832 — ffmpeg (9 hallazgos)

Fuente verificada: [Debian Security Tracker](https://security-tracker.debian.org/tracker/CVE-2026-64832); consulta `2026-11-10T01:23:38.2797542Z`. Estado: **open**; fixed aplicable: **ausente**.

Corrección mínima: Bloqueado: Debian trixie mantiene ffmpeg/CVE-2026-64832 abierto y no publica fixed_version para esta suite. Ningún pin corregido respaldado; no usar sid/forky ni declarar remediado por actualizar el snapshot.

Repositorios de trixie observados: {"trixie": "7:7.1.5-0+deb13u1", "trixie-security": "7:7.1.5-0+deb13u1"}.

| ID | Paquete binario @ instalada | Source @ versión | SrcName crudo | Severidad / SeveritySource | Status / DataSource.ID | FixedVersion crudo | Ámbito |
|---|---|---|---|---|---|---|---|
| F046 | ffmpeg @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |
| F047 | libavcodec61 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |
| F048 | libavdevice61 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |
| F049 | libavfilter10 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |
| F050 | libavformat61 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |
| F051 | libavutil59 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |
| F052 | libpostproc58 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |
| F053 | libswresample5 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |
| F054 | libswscale8 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |

Introductor y origen por fila:

- **F046:** APT CI explícito: ffmpeg. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F047:** APT CI explícito: ffmpeg → libavcodec61. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F048:** APT CI explícito: ffmpeg → libavdevice61. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F049:** APT CI explícito: ffmpeg → libavfilter10. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F050:** APT CI explícito: ffmpeg → libavformat61. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F051:** APT CI explícito: ffmpeg → libavutil59. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F052:** APT CI explícito: ffmpeg → libpostproc58. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F053:** APT CI explícito: ffmpeg → libswresample5. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F054:** APT CI explícito: ffmpeg → libswscale8. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.

### CVE-2026-64833 — ffmpeg (9 hallazgos)

Fuente verificada: [Debian Security Tracker](https://security-tracker.debian.org/tracker/CVE-2026-64833); consulta `2026-11-10T01:23:38.2797542Z`. Estado: **open**; fixed aplicable: **ausente**.

Corrección mínima: Bloqueado: Debian trixie mantiene ffmpeg/CVE-2026-64833 abierto y no publica fixed_version para esta suite. Ningún pin corregido respaldado; no usar sid/forky ni declarar remediado por actualizar el snapshot.

Repositorios de trixie observados: {"trixie": "7:7.1.5-0+deb13u1", "trixie-security": "7:7.1.5-0+deb13u1"}.

| ID | Paquete binario @ instalada | Source @ versión | SrcName crudo | Severidad / SeveritySource | Status / DataSource.ID | FixedVersion crudo | Ámbito |
|---|---|---|---|---|---|---|---|
| F055 | ffmpeg @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |
| F056 | libavcodec61 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |
| F057 | libavdevice61 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |
| F058 | libavfilter10 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |
| F059 | libavformat61 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |
| F060 | libavutil59 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |
| F061 | libpostproc58 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |
| F062 | libswresample5 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |
| F063 | libswscale8 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |

Introductor y origen por fila:

- **F055:** APT CI explícito: ffmpeg. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F056:** APT CI explícito: ffmpeg → libavcodec61. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F057:** APT CI explícito: ffmpeg → libavdevice61. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F058:** APT CI explícito: ffmpeg → libavfilter10. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F059:** APT CI explícito: ffmpeg → libavformat61. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F060:** APT CI explícito: ffmpeg → libavutil59. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F061:** APT CI explícito: ffmpeg → libpostproc58. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F062:** APT CI explícito: ffmpeg → libswresample5. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F063:** APT CI explícito: ffmpeg → libswscale8. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.

### CVE-2026-64834 — ffmpeg (9 hallazgos)

Fuente verificada: [Debian Security Tracker](https://security-tracker.debian.org/tracker/CVE-2026-64834); consulta `2026-11-10T01:23:38.2797542Z`. Estado: **open**; fixed aplicable: **ausente**.

Corrección mínima: Bloqueado: Debian trixie mantiene ffmpeg/CVE-2026-64834 abierto y no publica fixed_version para esta suite. Ningún pin corregido respaldado; no usar sid/forky ni declarar remediado por actualizar el snapshot.

Repositorios de trixie observados: {"trixie": "7:7.1.5-0+deb13u1", "trixie-security": "7:7.1.5-0+deb13u1"}.

| ID | Paquete binario @ instalada | Source @ versión | SrcName crudo | Severidad / SeveritySource | Status / DataSource.ID | FixedVersion crudo | Ámbito |
|---|---|---|---|---|---|---|---|
| F064 | ffmpeg @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |
| F065 | libavcodec61 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |
| F066 | libavdevice61 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |
| F067 | libavfilter10 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |
| F068 | libavformat61 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |
| F069 | libavutil59 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |
| F070 | libpostproc58 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |
| F071 | libswresample5 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |
| F072 | libswscale8 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |

Introductor y origen por fila:

- **F064:** APT CI explícito: ffmpeg. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F065:** APT CI explícito: ffmpeg → libavcodec61. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F066:** APT CI explícito: ffmpeg → libavdevice61. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F067:** APT CI explícito: ffmpeg → libavfilter10. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F068:** APT CI explícito: ffmpeg → libavformat61. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F069:** APT CI explícito: ffmpeg → libavutil59. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F070:** APT CI explícito: ffmpeg → libpostproc58. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F071:** APT CI explícito: ffmpeg → libswresample5. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F072:** APT CI explícito: ffmpeg → libswscale8. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.

### CVE-2026-64835 — ffmpeg (9 hallazgos)

Fuente verificada: [Debian Security Tracker](https://security-tracker.debian.org/tracker/CVE-2026-64835); consulta `2026-11-10T01:23:38.2797542Z`. Estado: **open**; fixed aplicable: **ausente**.

Corrección mínima: Bloqueado: Debian trixie mantiene ffmpeg/CVE-2026-64835 abierto y no publica fixed_version para esta suite. Ningún pin corregido respaldado; no usar sid/forky ni declarar remediado por actualizar el snapshot.

Repositorios de trixie observados: {"trixie": "7:7.1.5-0+deb13u1", "trixie-security": "7:7.1.5-0+deb13u1"}.

| ID | Paquete binario @ instalada | Source @ versión | SrcName crudo | Severidad / SeveritySource | Status / DataSource.ID | FixedVersion crudo | Ámbito |
|---|---|---|---|---|---|---|---|
| F073 | ffmpeg @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |
| F074 | libavcodec61 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |
| F075 | libavdevice61 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |
| F076 | libavfilter10 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |
| F077 | libavformat61 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |
| F078 | libavutil59 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |
| F079 | libpostproc58 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |
| F080 | libswresample5 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |
| F081 | libswscale8 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |

Introductor y origen por fila:

- **F073:** APT CI explícito: ffmpeg. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F074:** APT CI explícito: ffmpeg → libavcodec61. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F075:** APT CI explícito: ffmpeg → libavdevice61. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F076:** APT CI explícito: ffmpeg → libavfilter10. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F077:** APT CI explícito: ffmpeg → libavformat61. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F078:** APT CI explícito: ffmpeg → libavutil59. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F079:** APT CI explícito: ffmpeg → libpostproc58. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F080:** APT CI explícito: ffmpeg → libswresample5. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F081:** APT CI explícito: ffmpeg → libswscale8. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.

### CVE-2026-66036 — ffmpeg (9 hallazgos)

Fuente verificada: [Debian Security Tracker](https://security-tracker.debian.org/tracker/CVE-2026-66036); consulta `2026-11-10T01:23:38.2797542Z`. Estado: **open**; fixed aplicable: **ausente**.

Corrección mínima: Bloqueado: Debian trixie mantiene ffmpeg/CVE-2026-66036 abierto y no publica fixed_version para esta suite. Ningún pin corregido respaldado; no usar sid/forky ni declarar remediado por actualizar el snapshot.

Repositorios de trixie observados: {"trixie": "7:7.1.5-0+deb13u1", "trixie-security": "7:7.1.5-0+deb13u1"}.

| ID | Paquete binario @ instalada | Source @ versión | SrcName crudo | Severidad / SeveritySource | Status / DataSource.ID | FixedVersion crudo | Ámbito |
|---|---|---|---|---|---|---|---|
| F082 | ffmpeg @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / nvd | fix_deferred / debian | ausente | sistema |
| F083 | libavcodec61 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / nvd | fix_deferred / debian | ausente | sistema |
| F084 | libavdevice61 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / nvd | fix_deferred / debian | ausente | sistema |
| F085 | libavfilter10 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / nvd | fix_deferred / debian | ausente | sistema |
| F086 | libavformat61 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / nvd | fix_deferred / debian | ausente | sistema |
| F087 | libavutil59 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / nvd | fix_deferred / debian | ausente | sistema |
| F088 | libpostproc58 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / nvd | fix_deferred / debian | ausente | sistema |
| F089 | libswresample5 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / nvd | fix_deferred / debian | ausente | sistema |
| F090 | libswscale8 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / nvd | fix_deferred / debian | ausente | sistema |

Introductor y origen por fila:

- **F082:** APT CI explícito: ffmpeg. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F083:** APT CI explícito: ffmpeg → libavcodec61. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F084:** APT CI explícito: ffmpeg → libavdevice61. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F085:** APT CI explícito: ffmpeg → libavfilter10. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F086:** APT CI explícito: ffmpeg → libavformat61. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F087:** APT CI explícito: ffmpeg → libavutil59. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F088:** APT CI explícito: ffmpeg → libpostproc58. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F089:** APT CI explícito: ffmpeg → libswresample5. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F090:** APT CI explícito: ffmpeg → libswscale8. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.

### CVE-2026-66039 — ffmpeg (9 hallazgos)

Fuente verificada: [Debian Security Tracker](https://security-tracker.debian.org/tracker/CVE-2026-66039); consulta `2026-11-10T01:23:38.2797542Z`. Estado: **open**; fixed aplicable: **ausente**.

Corrección mínima: Bloqueado: Debian trixie mantiene ffmpeg/CVE-2026-66039 abierto y no publica fixed_version para esta suite. Ningún pin corregido respaldado; no usar sid/forky ni declarar remediado por actualizar el snapshot.

Repositorios de trixie observados: {"trixie": "7:7.1.5-0+deb13u1", "trixie-security": "7:7.1.5-0+deb13u1"}.

| ID | Paquete binario @ instalada | Source @ versión | SrcName crudo | Severidad / SeveritySource | Status / DataSource.ID | FixedVersion crudo | Ámbito |
|---|---|---|---|---|---|---|---|
| F091 | ffmpeg @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / nvd | fix_deferred / debian | ausente | sistema |
| F092 | libavcodec61 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / nvd | fix_deferred / debian | ausente | sistema |
| F093 | libavdevice61 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / nvd | fix_deferred / debian | ausente | sistema |
| F094 | libavfilter10 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / nvd | fix_deferred / debian | ausente | sistema |
| F095 | libavformat61 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / nvd | fix_deferred / debian | ausente | sistema |
| F096 | libavutil59 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / nvd | fix_deferred / debian | ausente | sistema |
| F097 | libpostproc58 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / nvd | fix_deferred / debian | ausente | sistema |
| F098 | libswresample5 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / nvd | fix_deferred / debian | ausente | sistema |
| F099 | libswscale8 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / nvd | fix_deferred / debian | ausente | sistema |

Introductor y origen por fila:

- **F091:** APT CI explícito: ffmpeg. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F092:** APT CI explícito: ffmpeg → libavcodec61. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F093:** APT CI explícito: ffmpeg → libavdevice61. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F094:** APT CI explícito: ffmpeg → libavfilter10. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F095:** APT CI explícito: ffmpeg → libavformat61. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F096:** APT CI explícito: ffmpeg → libavutil59. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F097:** APT CI explícito: ffmpeg → libpostproc58. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F098:** APT CI explícito: ffmpeg → libswresample5. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F099:** APT CI explícito: ffmpeg → libswscale8. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.

### CVE-2026-66040 — ffmpeg (9 hallazgos)

Fuente verificada: [Debian Security Tracker](https://security-tracker.debian.org/tracker/CVE-2026-66040); consulta `2026-11-10T01:23:38.2797542Z`. Estado: **open**; fixed aplicable: **ausente**.

Corrección mínima: Bloqueado: Debian trixie mantiene ffmpeg/CVE-2026-66040 abierto y no publica fixed_version para esta suite. Ningún pin corregido respaldado; no usar sid/forky ni declarar remediado por actualizar el snapshot.

Repositorios de trixie observados: {"trixie": "7:7.1.5-0+deb13u1", "trixie-security": "7:7.1.5-0+deb13u1"}.

| ID | Paquete binario @ instalada | Source @ versión | SrcName crudo | Severidad / SeveritySource | Status / DataSource.ID | FixedVersion crudo | Ámbito |
|---|---|---|---|---|---|---|---|
| F100 | ffmpeg @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / nvd | fix_deferred / debian | ausente | sistema |
| F101 | libavcodec61 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / nvd | fix_deferred / debian | ausente | sistema |
| F102 | libavdevice61 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / nvd | fix_deferred / debian | ausente | sistema |
| F103 | libavfilter10 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / nvd | fix_deferred / debian | ausente | sistema |
| F104 | libavformat61 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / nvd | fix_deferred / debian | ausente | sistema |
| F105 | libavutil59 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / nvd | fix_deferred / debian | ausente | sistema |
| F106 | libpostproc58 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / nvd | fix_deferred / debian | ausente | sistema |
| F107 | libswresample5 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / nvd | fix_deferred / debian | ausente | sistema |
| F108 | libswscale8 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / nvd | fix_deferred / debian | ausente | sistema |

Introductor y origen por fila:

- **F100:** APT CI explícito: ffmpeg. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F101:** APT CI explícito: ffmpeg → libavcodec61. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F102:** APT CI explícito: ffmpeg → libavdevice61. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F103:** APT CI explícito: ffmpeg → libavfilter10. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F104:** APT CI explícito: ffmpeg → libavformat61. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F105:** APT CI explícito: ffmpeg → libavutil59. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F106:** APT CI explícito: ffmpeg → libpostproc58. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F107:** APT CI explícito: ffmpeg → libswresample5. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F108:** APT CI explícito: ffmpeg → libswscale8. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.

### CVE-2026-66041 — ffmpeg (9 hallazgos)

Fuente verificada: [Debian Security Tracker](https://security-tracker.debian.org/tracker/CVE-2026-66041); consulta `2026-11-10T01:23:38.2797542Z`. Estado: **open**; fixed aplicable: **ausente**.

Corrección mínima: Bloqueado: Debian trixie mantiene ffmpeg/CVE-2026-66041 abierto y no publica fixed_version para esta suite. Ningún pin corregido respaldado; no usar sid/forky ni declarar remediado por actualizar el snapshot.

Repositorios de trixie observados: {"trixie": "7:7.1.5-0+deb13u1", "trixie-security": "7:7.1.5-0+deb13u1"}.

| ID | Paquete binario @ instalada | Source @ versión | SrcName crudo | Severidad / SeveritySource | Status / DataSource.ID | FixedVersion crudo | Ámbito |
|---|---|---|---|---|---|---|---|
| F109 | ffmpeg @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / nvd | fix_deferred / debian | ausente | sistema |
| F110 | libavcodec61 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / nvd | fix_deferred / debian | ausente | sistema |
| F111 | libavdevice61 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / nvd | fix_deferred / debian | ausente | sistema |
| F112 | libavfilter10 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / nvd | fix_deferred / debian | ausente | sistema |
| F113 | libavformat61 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / nvd | fix_deferred / debian | ausente | sistema |
| F114 | libavutil59 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / nvd | fix_deferred / debian | ausente | sistema |
| F115 | libpostproc58 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / nvd | fix_deferred / debian | ausente | sistema |
| F116 | libswresample5 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / nvd | fix_deferred / debian | ausente | sistema |
| F117 | libswscale8 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / nvd | fix_deferred / debian | ausente | sistema |

Introductor y origen por fila:

- **F109:** APT CI explícito: ffmpeg. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F110:** APT CI explícito: ffmpeg → libavcodec61. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F111:** APT CI explícito: ffmpeg → libavdevice61. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F112:** APT CI explícito: ffmpeg → libavfilter10. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F113:** APT CI explícito: ffmpeg → libavformat61. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F114:** APT CI explícito: ffmpeg → libavutil59. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F115:** APT CI explícito: ffmpeg → libpostproc58. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F116:** APT CI explícito: ffmpeg → libswresample5. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F117:** APT CI explícito: ffmpeg → libswscale8. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.

### CVE-2026-6653 — libxml2 (1 hallazgos)

Fuente verificada: [Debian Security Tracker](https://security-tracker.debian.org/tracker/CVE-2026-6653); consulta `2026-11-10T01:23:38.2797542Z`. Estado: **open**; fixed aplicable: **ausente**.

Corrección mínima: Bloqueado: Debian trixie mantiene libxml2/CVE-2026-6653 abierto y no publica fixed_version para esta suite. Ningún pin corregido respaldado; no usar sid/forky ni declarar remediado por actualizar el snapshot.

Repositorios de trixie observados: {"trixie": "2.12.7+dfsg+really2.9.14-2.1+deb13u3", "trixie-security": "2.12.7+dfsg+really2.9.14-2.1+deb13u1"}.

| ID | Paquete binario @ instalada | Source @ versión | SrcName crudo | Severidad / SeveritySource | Status / DataSource.ID | FixedVersion crudo | Ámbito |
|---|---|---|---|---|---|---|---|
| F118 | libxml2 @ 2.12.7+dfsg+really2.9.14-2.1+deb13u3 | libxml2 @ 2.12.7+dfsg+really2.9.14-2.1+deb13u3 | ausente | CRITICAL / nvd | affected / debian | ausente | sistema |

Introductor y origen por fila:

- **F118:** APT CI explícito: ffmpeg → libavformat61 → libxml2. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.

### CVE-2026-67215 — cjson (1 hallazgos)

Fuente verificada: [Debian Security Tracker](https://security-tracker.debian.org/tracker/CVE-2026-67215); consulta `2026-11-10T01:23:38.2797542Z`. Estado: **open**; fixed aplicable: **ausente**.

Corrección mínima: Bloqueado: Debian trixie mantiene cjson/CVE-2026-67215 abierto y no publica fixed_version para esta suite. Ningún pin corregido respaldado; no usar sid/forky ni declarar remediado por actualizar el snapshot.

Repositorios de trixie observados: {"trixie": "1.7.18-3.1+deb13u1", "trixie-security": "1.7.18-3.1+deb13u1"}.

| ID | Paquete binario @ instalada | Source @ versión | SrcName crudo | Severidad / SeveritySource | Status / DataSource.ID | FixedVersion crudo | Ámbito |
|---|---|---|---|---|---|---|---|
| F119 | libcjson1 @ 1.7.18-3.1+deb13u1 | cjson @ 1.7.18-3.1+deb13u1 | ausente | HIGH / ausente | affected / debian | ausente | sistema |

Introductor y origen por fila:

- **F119:** APT CI explícito: ffmpeg → libavformat61 → librist4 → libcjson1. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.

### CVE-2026-67216 — cjson (1 hallazgos)

Fuente verificada: [Debian Security Tracker](https://security-tracker.debian.org/tracker/CVE-2026-67216); consulta `2026-11-10T01:23:38.2797542Z`. Estado: **open**; fixed aplicable: **ausente**.

Corrección mínima: Bloqueado: Debian trixie mantiene cjson/CVE-2026-67216 abierto y no publica fixed_version para esta suite. Ningún pin corregido respaldado; no usar sid/forky ni declarar remediado por actualizar el snapshot.

Repositorios de trixie observados: {"trixie": "1.7.18-3.1+deb13u1", "trixie-security": "1.7.18-3.1+deb13u1"}.

| ID | Paquete binario @ instalada | Source @ versión | SrcName crudo | Severidad / SeveritySource | Status / DataSource.ID | FixedVersion crudo | Ámbito |
|---|---|---|---|---|---|---|---|
| F120 | libcjson1 @ 1.7.18-3.1+deb13u1 | cjson @ 1.7.18-3.1+deb13u1 | ausente | HIGH / nvd | affected / debian | ausente | sistema |

Introductor y origen por fila:

- **F120:** APT CI explícito: ffmpeg → libavformat61 → librist4 → libcjson1. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.

### CVE-2026-70628 — ffmpeg (9 hallazgos)

Fuente verificada: [Debian Security Tracker](https://security-tracker.debian.org/tracker/CVE-2026-70628); consulta `2026-11-10T01:23:38.2797542Z`. Estado: **open**; fixed aplicable: **ausente**.

Corrección mínima: Bloqueado: Debian trixie mantiene ffmpeg/CVE-2026-70628 abierto y no publica fixed_version para esta suite. Ningún pin corregido respaldado; no usar sid/forky ni declarar remediado por actualizar el snapshot.

Repositorios de trixie observados: {"trixie": "7:7.1.5-0+deb13u1", "trixie-security": "7:7.1.5-0+deb13u1"}.

| ID | Paquete binario @ instalada | Source @ versión | SrcName crudo | Severidad / SeveritySource | Status / DataSource.ID | FixedVersion crudo | Ámbito |
|---|---|---|---|---|---|---|---|
| F121 | ffmpeg @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |
| F122 | libavcodec61 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |
| F123 | libavdevice61 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |
| F124 | libavfilter10 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |
| F125 | libavformat61 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |
| F126 | libavutil59 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |
| F127 | libpostproc58 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |
| F128 | libswresample5 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |
| F129 | libswscale8 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |

Introductor y origen por fila:

- **F121:** APT CI explícito: ffmpeg. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F122:** APT CI explícito: ffmpeg → libavcodec61. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F123:** APT CI explícito: ffmpeg → libavdevice61. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F124:** APT CI explícito: ffmpeg → libavfilter10. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F125:** APT CI explícito: ffmpeg → libavformat61. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F126:** APT CI explícito: ffmpeg → libavutil59. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F127:** APT CI explícito: ffmpeg → libpostproc58. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F128:** APT CI explícito: ffmpeg → libswresample5. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F129:** APT CI explícito: ffmpeg → libswscale8. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.

### CVE-2026-70632 — ffmpeg (9 hallazgos)

Fuente verificada: [Debian Security Tracker](https://security-tracker.debian.org/tracker/CVE-2026-70632); consulta `2026-11-10T01:23:38.2797542Z`. Estado: **open**; fixed aplicable: **ausente**.

Corrección mínima: Bloqueado: Debian trixie mantiene ffmpeg/CVE-2026-70632 abierto y no publica fixed_version para esta suite. Ningún pin corregido respaldado; no usar sid/forky ni declarar remediado por actualizar el snapshot.

Repositorios de trixie observados: {"trixie": "7:7.1.5-0+deb13u1", "trixie-security": "7:7.1.5-0+deb13u1"}.

| ID | Paquete binario @ instalada | Source @ versión | SrcName crudo | Severidad / SeveritySource | Status / DataSource.ID | FixedVersion crudo | Ámbito |
|---|---|---|---|---|---|---|---|
| F130 | ffmpeg @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |
| F131 | libavcodec61 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |
| F132 | libavdevice61 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |
| F133 | libavfilter10 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |
| F134 | libavformat61 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |
| F135 | libavutil59 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |
| F136 | libpostproc58 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |
| F137 | libswresample5 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |
| F138 | libswscale8 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |

Introductor y origen por fila:

- **F130:** APT CI explícito: ffmpeg. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F131:** APT CI explícito: ffmpeg → libavcodec61. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F132:** APT CI explícito: ffmpeg → libavdevice61. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F133:** APT CI explícito: ffmpeg → libavfilter10. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F134:** APT CI explícito: ffmpeg → libavformat61. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F135:** APT CI explícito: ffmpeg → libavutil59. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F136:** APT CI explícito: ffmpeg → libpostproc58. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F137:** APT CI explícito: ffmpeg → libswresample5. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F138:** APT CI explícito: ffmpeg → libswscale8. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.

### CVE-2026-74860 — libxml2 (1 hallazgos)

Fuente verificada: [Debian Security Tracker](https://security-tracker.debian.org/tracker/CVE-2026-74860); consulta `2026-11-10T01:23:38.2797542Z`. Estado: **open**; fixed aplicable: **ausente**.

Corrección mínima: Bloqueado: Debian trixie mantiene libxml2/CVE-2026-74860 abierto y no publica fixed_version para esta suite. Ningún pin corregido respaldado; no usar sid/forky ni declarar remediado por actualizar el snapshot.

Repositorios de trixie observados: {"trixie": "2.12.7+dfsg+really2.9.14-2.1+deb13u3", "trixie-security": "2.12.7+dfsg+really2.9.14-2.1+deb13u1"}.

| ID | Paquete binario @ instalada | Source @ versión | SrcName crudo | Severidad / SeveritySource | Status / DataSource.ID | FixedVersion crudo | Ámbito |
|---|---|---|---|---|---|---|---|
| F139 | libxml2 @ 2.12.7+dfsg+really2.9.14-2.1+deb13u3 | libxml2 @ 2.12.7+dfsg+really2.9.14-2.1+deb13u3 | ausente | HIGH / ausente | affected / debian | ausente | sistema |

Introductor y origen por fila:

- **F139:** APT CI explícito: ffmpeg → libavformat61 → libxml2. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.

### CVE-2026-75141 — ffmpeg (9 hallazgos)

Fuente verificada: [Debian Security Tracker](https://security-tracker.debian.org/tracker/CVE-2026-75141); consulta `2026-11-10T01:23:38.2797542Z`. Estado: **open**; fixed aplicable: **ausente**.

Corrección mínima: Bloqueado: Debian trixie mantiene ffmpeg/CVE-2026-75141 abierto y no publica fixed_version para esta suite. Ningún pin corregido respaldado; no usar sid/forky ni declarar remediado por actualizar el snapshot.

Repositorios de trixie observados: {"trixie": "7:7.1.5-0+deb13u1", "trixie-security": "7:7.1.5-0+deb13u1"}.

| ID | Paquete binario @ instalada | Source @ versión | SrcName crudo | Severidad / SeveritySource | Status / DataSource.ID | FixedVersion crudo | Ámbito |
|---|---|---|---|---|---|---|---|
| F140 | ffmpeg @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |
| F141 | libavcodec61 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |
| F142 | libavdevice61 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |
| F143 | libavfilter10 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |
| F144 | libavformat61 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |
| F145 | libavutil59 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |
| F146 | libpostproc58 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |
| F147 | libswresample5 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |
| F148 | libswscale8 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |

Introductor y origen por fila:

- **F140:** APT CI explícito: ffmpeg. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F141:** APT CI explícito: ffmpeg → libavcodec61. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F142:** APT CI explícito: ffmpeg → libavdevice61. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F143:** APT CI explícito: ffmpeg → libavfilter10. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F144:** APT CI explícito: ffmpeg → libavformat61. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F145:** APT CI explícito: ffmpeg → libavutil59. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F146:** APT CI explícito: ffmpeg → libpostproc58. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F147:** APT CI explícito: ffmpeg → libswresample5. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F148:** APT CI explícito: ffmpeg → libswscale8. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.

### CVE-2026-75142 — ffmpeg (9 hallazgos)

Fuente verificada: [Debian Security Tracker](https://security-tracker.debian.org/tracker/CVE-2026-75142); consulta `2026-11-10T01:23:38.2797542Z`. Estado: **open**; fixed aplicable: **ausente**.

Corrección mínima: Bloqueado: Debian trixie mantiene ffmpeg/CVE-2026-75142 abierto y no publica fixed_version para esta suite. Ningún pin corregido respaldado; no usar sid/forky ni declarar remediado por actualizar el snapshot.

Repositorios de trixie observados: {"trixie": "7:7.1.5-0+deb13u1", "trixie-security": "7:7.1.5-0+deb13u1"}.

| ID | Paquete binario @ instalada | Source @ versión | SrcName crudo | Severidad / SeveritySource | Status / DataSource.ID | FixedVersion crudo | Ámbito |
|---|---|---|---|---|---|---|---|
| F149 | ffmpeg @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |
| F150 | libavcodec61 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |
| F151 | libavdevice61 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |
| F152 | libavfilter10 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |
| F153 | libavformat61 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |
| F154 | libavutil59 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |
| F155 | libpostproc58 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |
| F156 | libswresample5 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |
| F157 | libswscale8 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |

Introductor y origen por fila:

- **F149:** APT CI explícito: ffmpeg. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F150:** APT CI explícito: ffmpeg → libavcodec61. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F151:** APT CI explícito: ffmpeg → libavdevice61. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F152:** APT CI explícito: ffmpeg → libavfilter10. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F153:** APT CI explícito: ffmpeg → libavformat61. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F154:** APT CI explícito: ffmpeg → libavutil59. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F155:** APT CI explícito: ffmpeg → libpostproc58. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F156:** APT CI explícito: ffmpeg → libswresample5. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F157:** APT CI explícito: ffmpeg → libswscale8. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.

### CVE-2026-75143 — ffmpeg (9 hallazgos)

Fuente verificada: [Debian Security Tracker](https://security-tracker.debian.org/tracker/CVE-2026-75143); consulta `2026-11-10T01:23:38.2797542Z`. Estado: **open**; fixed aplicable: **ausente**.

Corrección mínima: Bloqueado: Debian trixie mantiene ffmpeg/CVE-2026-75143 abierto y no publica fixed_version para esta suite. Ningún pin corregido respaldado; no usar sid/forky ni declarar remediado por actualizar el snapshot.

Repositorios de trixie observados: {"trixie": "7:7.1.5-0+deb13u1", "trixie-security": "7:7.1.5-0+deb13u1"}.

| ID | Paquete binario @ instalada | Source @ versión | SrcName crudo | Severidad / SeveritySource | Status / DataSource.ID | FixedVersion crudo | Ámbito |
|---|---|---|---|---|---|---|---|
| F158 | ffmpeg @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |
| F159 | libavcodec61 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |
| F160 | libavdevice61 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |
| F161 | libavfilter10 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |
| F162 | libavformat61 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |
| F163 | libavutil59 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |
| F164 | libpostproc58 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |
| F165 | libswresample5 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |
| F166 | libswscale8 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |

Introductor y origen por fila:

- **F158:** APT CI explícito: ffmpeg. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F159:** APT CI explícito: ffmpeg → libavcodec61. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F160:** APT CI explícito: ffmpeg → libavdevice61. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F161:** APT CI explícito: ffmpeg → libavfilter10. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F162:** APT CI explícito: ffmpeg → libavformat61. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F163:** APT CI explícito: ffmpeg → libavutil59. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F164:** APT CI explícito: ffmpeg → libpostproc58. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F165:** APT CI explícito: ffmpeg → libswresample5. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F166:** APT CI explícito: ffmpeg → libswscale8. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.

### CVE-2026-75144 — ffmpeg (9 hallazgos)

Fuente verificada: [Debian Security Tracker](https://security-tracker.debian.org/tracker/CVE-2026-75144); consulta `2026-11-10T01:23:38.2797542Z`. Estado: **open**; fixed aplicable: **ausente**.

Corrección mínima: Bloqueado: Debian trixie mantiene ffmpeg/CVE-2026-75144 abierto y no publica fixed_version para esta suite. Ningún pin corregido respaldado; no usar sid/forky ni declarar remediado por actualizar el snapshot.

Repositorios de trixie observados: {"trixie": "7:7.1.5-0+deb13u1", "trixie-security": "7:7.1.5-0+deb13u1"}.

| ID | Paquete binario @ instalada | Source @ versión | SrcName crudo | Severidad / SeveritySource | Status / DataSource.ID | FixedVersion crudo | Ámbito |
|---|---|---|---|---|---|---|---|
| F167 | ffmpeg @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |
| F168 | libavcodec61 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |
| F169 | libavdevice61 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |
| F170 | libavfilter10 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |
| F171 | libavformat61 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |
| F172 | libavutil59 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |
| F173 | libpostproc58 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |
| F174 | libswresample5 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |
| F175 | libswscale8 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |

Introductor y origen por fila:

- **F167:** APT CI explícito: ffmpeg. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F168:** APT CI explícito: ffmpeg → libavcodec61. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F169:** APT CI explícito: ffmpeg → libavdevice61. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F170:** APT CI explícito: ffmpeg → libavfilter10. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F171:** APT CI explícito: ffmpeg → libavformat61. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F172:** APT CI explícito: ffmpeg → libavutil59. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F173:** APT CI explícito: ffmpeg → libpostproc58. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F174:** APT CI explícito: ffmpeg → libswresample5. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F175:** APT CI explícito: ffmpeg → libswscale8. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.

### CVE-2026-75146 — ffmpeg (9 hallazgos)

Fuente verificada: [Debian Security Tracker](https://security-tracker.debian.org/tracker/CVE-2026-75146); consulta `2026-11-10T01:23:38.2797542Z`. Estado: **open**; fixed aplicable: **ausente**.

Corrección mínima: Bloqueado: Debian trixie mantiene ffmpeg/CVE-2026-75146 abierto y no publica fixed_version para esta suite. Ningún pin corregido respaldado; no usar sid/forky ni declarar remediado por actualizar el snapshot.

Repositorios de trixie observados: {"trixie": "7:7.1.5-0+deb13u1", "trixie-security": "7:7.1.5-0+deb13u1"}.

| ID | Paquete binario @ instalada | Source @ versión | SrcName crudo | Severidad / SeveritySource | Status / DataSource.ID | FixedVersion crudo | Ámbito |
|---|---|---|---|---|---|---|---|
| F176 | ffmpeg @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |
| F177 | libavcodec61 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |
| F178 | libavdevice61 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |
| F179 | libavfilter10 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |
| F180 | libavformat61 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |
| F181 | libavutil59 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |
| F182 | libpostproc58 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |
| F183 | libswresample5 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |
| F184 | libswscale8 @ 7:7.1.5-0+deb13u1 | ffmpeg @ 7:7.1.5-0+deb13u1 | ausente | HIGH / ausente | fix_deferred / debian | ausente | sistema |

Introductor y origen por fila:

- **F176:** APT CI explícito: ffmpeg. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F177:** APT CI explícito: ffmpeg → libavcodec61. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F178:** APT CI explícito: ffmpeg → libavdevice61. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F179:** APT CI explícito: ffmpeg → libavfilter10. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F180:** APT CI explícito: ffmpeg → libavformat61. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F181:** APT CI explícito: ffmpeg → libavutil59. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F182:** APT CI explícito: ffmpeg → libpostproc58. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F183:** APT CI explícito: ffmpeg → libswresample5. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F184:** APT CI explícito: ffmpeg → libswscale8. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.

### CVE-2026-76642 — util-linux (9 hallazgos)

Fuente verificada: [Debian Security Tracker](https://security-tracker.debian.org/tracker/CVE-2026-76642); consulta `2026-11-10T01:23:38.2797542Z`. Estado: **open**; fixed aplicable: **ausente**.

Corrección mínima: Bloqueado: Debian trixie mantiene util-linux/CVE-2026-76642 abierto y no publica fixed_version para esta suite. Ningún pin corregido respaldado; no usar sid/forky ni declarar remediado por actualizar el snapshot.

Repositorios de trixie observados: {"trixie": "2.41.5-0+deb13u1", "trixie-security": "2.41.5-0+deb13u1"}.

| ID | Paquete binario @ instalada | Source @ versión | SrcName crudo | Severidad / SeveritySource | Status / DataSource.ID | FixedVersion crudo | Ámbito |
|---|---|---|---|---|---|---|---|
| F185 | bsdutils @ 1:2.41.5-0+deb13u1 | util-linux @ 2.41.5-0+deb13u1 | ausente | HIGH / ausente | affected / debian | ausente | sistema |
| F186 | libblkid1 @ 2.41.5-0+deb13u1 | util-linux @ 2.41.5-0+deb13u1 | ausente | HIGH / ausente | affected / debian | ausente | sistema |
| F187 | liblastlog2-2 @ 2.41.5-0+deb13u1 | util-linux @ 2.41.5-0+deb13u1 | ausente | HIGH / ausente | affected / debian | ausente | sistema |
| F188 | libmount1 @ 2.41.5-0+deb13u1 | util-linux @ 2.41.5-0+deb13u1 | ausente | HIGH / ausente | affected / debian | ausente | sistema |
| F189 | libsmartcols1 @ 2.41.5-0+deb13u1 | util-linux @ 2.41.5-0+deb13u1 | ausente | HIGH / ausente | affected / debian | ausente | sistema |
| F190 | libuuid1 @ 2.41.5-0+deb13u1 | util-linux @ 2.41.5-0+deb13u1 | ausente | HIGH / ausente | affected / debian | ausente | sistema |
| F191 | login @ 1:4.16.0-2+really2.41.5-0+deb13u1 | util-linux @ 2.41.5-0+deb13u1 | ausente | HIGH / ausente | affected / debian | ausente | sistema |
| F192 | mount @ 2.41.5-0+deb13u1 | util-linux @ 2.41.5-0+deb13u1 | ausente | HIGH / ausente | affected / debian | ausente | sistema |
| F193 | util-linux @ 2.41.5-0+deb13u1 | util-linux @ 2.41.5-0+deb13u1 | ausente | HIGH / ausente | affected / debian | ausente | sistema |

Introductor y origen por fila:

- **F185:** Base Python/Debian (inferencia por capa); introductor concreto no identificado. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DiffID observado, sin inventar una arista de dependencia. Regresiones: OS.
- **F186:** APT CI explícito: ffmpeg → libavcodec61 → libglib2.0-0t64 → libmount1 → libblkid1. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F187:** Base Python/Debian (inferencia por capa); introductor concreto no identificado. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DiffID observado, sin inventar una arista de dependencia. Regresiones: OS.
- **F188:** APT CI explícito: ffmpeg → libavcodec61 → libglib2.0-0t64 → libmount1. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F189:** Base Python/Debian (inferencia por capa); introductor concreto no identificado. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DiffID observado, sin inventar una arista de dependencia. Regresiones: OS.
- **F190:** Base Python/Debian (inferencia por capa); introductor concreto no identificado. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DiffID observado, sin inventar una arista de dependencia. Regresiones: OS.
- **F191:** Base Python/Debian (inferencia por capa); introductor concreto no identificado. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DiffID observado, sin inventar una arista de dependencia. Regresiones: OS.
- **F192:** Base Python/Debian (inferencia por capa); introductor concreto no identificado. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DiffID observado, sin inventar una arista de dependencia. Regresiones: OS.
- **F193:** Base Python/Debian (inferencia por capa); introductor concreto no identificado. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DiffID observado, sin inventar una arista de dependencia. Regresiones: OS.

### CVE-2026-76844 — zlib (1 hallazgos)

Fuente verificada: [Debian Security Tracker](https://security-tracker.debian.org/tracker/CVE-2026-76844); consulta `2026-11-10T01:23:38.2797542Z`. Estado: **resolved**; fixed aplicable: **1:1.3.dfsg+really1.3.1-1+deb13u1**.

Corrección mínima: Candidato de backport trixie: zlib 1:1.3.dfsg+really1.3.1-1+deb13u1; verificar binario exacto en APT del snapshot aprobado e instalar solo los paquetes necesarios. No ejecutado.

Repositorios de trixie observados: {"trixie": "1:1.3.dfsg+really1.3.1-1", "trixie-security": "1:1.3.dfsg+really1.3.1-1+deb13u1"}.

| ID | Paquete binario @ instalada | Source @ versión | SrcName crudo | Severidad / SeveritySource | Status / DataSource.ID | FixedVersion crudo | Ámbito |
|---|---|---|---|---|---|---|---|
| F194 | zlib1g @ 1:1.3.dfsg+really1.3.1-1+b1 | zlib @ 1:1.3.dfsg+really1.3.1-1 | ausente | HIGH / ausente | fixed / debian | 1:1.3.dfsg+really1.3.1-1+deb13u1 | sistema |

Introductor y origen por fila:

- **F194:** APT CI explícito: ffmpeg → libavcodec61 → zlib1g. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.

### CVE-2026-78408 — util-linux (9 hallazgos)

Fuente verificada: [Debian Security Tracker](https://security-tracker.debian.org/tracker/CVE-2026-78408); consulta `2026-11-10T01:23:38.2797542Z`. Estado: **open**; fixed aplicable: **ausente**.

Corrección mínima: Bloqueado: Debian trixie mantiene util-linux/CVE-2026-78408 abierto y no publica fixed_version para esta suite. Ningún pin corregido respaldado; no usar sid/forky ni declarar remediado por actualizar el snapshot.

Repositorios de trixie observados: {"trixie": "2.41.5-0+deb13u1", "trixie-security": "2.41.5-0+deb13u1"}.

| ID | Paquete binario @ instalada | Source @ versión | SrcName crudo | Severidad / SeveritySource | Status / DataSource.ID | FixedVersion crudo | Ámbito |
|---|---|---|---|---|---|---|---|
| F195 | bsdutils @ 1:2.41.5-0+deb13u1 | util-linux @ 2.41.5-0+deb13u1 | ausente | HIGH / ausente | affected / debian | ausente | sistema |
| F196 | libblkid1 @ 2.41.5-0+deb13u1 | util-linux @ 2.41.5-0+deb13u1 | ausente | HIGH / ausente | affected / debian | ausente | sistema |
| F197 | liblastlog2-2 @ 2.41.5-0+deb13u1 | util-linux @ 2.41.5-0+deb13u1 | ausente | HIGH / ausente | affected / debian | ausente | sistema |
| F198 | libmount1 @ 2.41.5-0+deb13u1 | util-linux @ 2.41.5-0+deb13u1 | ausente | HIGH / ausente | affected / debian | ausente | sistema |
| F199 | libsmartcols1 @ 2.41.5-0+deb13u1 | util-linux @ 2.41.5-0+deb13u1 | ausente | HIGH / ausente | affected / debian | ausente | sistema |
| F200 | libuuid1 @ 2.41.5-0+deb13u1 | util-linux @ 2.41.5-0+deb13u1 | ausente | HIGH / ausente | affected / debian | ausente | sistema |
| F201 | login @ 1:4.16.0-2+really2.41.5-0+deb13u1 | util-linux @ 2.41.5-0+deb13u1 | ausente | HIGH / ausente | affected / debian | ausente | sistema |
| F202 | mount @ 2.41.5-0+deb13u1 | util-linux @ 2.41.5-0+deb13u1 | ausente | HIGH / ausente | affected / debian | ausente | sistema |
| F203 | util-linux @ 2.41.5-0+deb13u1 | util-linux @ 2.41.5-0+deb13u1 | ausente | HIGH / ausente | affected / debian | ausente | sistema |

Introductor y origen por fila:

- **F195:** Base Python/Debian (inferencia por capa); introductor concreto no identificado. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DiffID observado, sin inventar una arista de dependencia. Regresiones: OS.
- **F196:** APT CI explícito: ffmpeg → libavcodec61 → libglib2.0-0t64 → libmount1 → libblkid1. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F197:** Base Python/Debian (inferencia por capa); introductor concreto no identificado. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DiffID observado, sin inventar una arista de dependencia. Regresiones: OS.
- **F198:** APT CI explícito: ffmpeg → libavcodec61 → libglib2.0-0t64 → libmount1. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F199:** Base Python/Debian (inferencia por capa); introductor concreto no identificado. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DiffID observado, sin inventar una arista de dependencia. Regresiones: OS.
- **F200:** Base Python/Debian (inferencia por capa); introductor concreto no identificado. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DiffID observado, sin inventar una arista de dependencia. Regresiones: OS.
- **F201:** Base Python/Debian (inferencia por capa); introductor concreto no identificado. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DiffID observado, sin inventar una arista de dependencia. Regresiones: OS.
- **F202:** Base Python/Debian (inferencia por capa); introductor concreto no identificado. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DiffID observado, sin inventar una arista de dependencia. Regresiones: OS.
- **F203:** Base Python/Debian (inferencia por capa); introductor concreto no identificado. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DiffID observado, sin inventar una arista de dependencia. Regresiones: OS.

### CVE-2026-78409 — util-linux (9 hallazgos)

Fuente verificada: [Debian Security Tracker](https://security-tracker.debian.org/tracker/CVE-2026-78409); consulta `2026-11-10T01:23:38.2797542Z`. Estado: **open**; fixed aplicable: **ausente**.

Corrección mínima: Bloqueado: Debian trixie mantiene util-linux/CVE-2026-78409 abierto y no publica fixed_version para esta suite. Ningún pin corregido respaldado; no usar sid/forky ni declarar remediado por actualizar el snapshot.

Repositorios de trixie observados: {"trixie": "2.41.5-0+deb13u1", "trixie-security": "2.41.5-0+deb13u1"}.

| ID | Paquete binario @ instalada | Source @ versión | SrcName crudo | Severidad / SeveritySource | Status / DataSource.ID | FixedVersion crudo | Ámbito |
|---|---|---|---|---|---|---|---|
| F204 | bsdutils @ 1:2.41.5-0+deb13u1 | util-linux @ 2.41.5-0+deb13u1 | ausente | HIGH / ausente | affected / debian | ausente | sistema |
| F205 | libblkid1 @ 2.41.5-0+deb13u1 | util-linux @ 2.41.5-0+deb13u1 | ausente | HIGH / ausente | affected / debian | ausente | sistema |
| F206 | liblastlog2-2 @ 2.41.5-0+deb13u1 | util-linux @ 2.41.5-0+deb13u1 | ausente | HIGH / ausente | affected / debian | ausente | sistema |
| F207 | libmount1 @ 2.41.5-0+deb13u1 | util-linux @ 2.41.5-0+deb13u1 | ausente | HIGH / ausente | affected / debian | ausente | sistema |
| F208 | libsmartcols1 @ 2.41.5-0+deb13u1 | util-linux @ 2.41.5-0+deb13u1 | ausente | HIGH / ausente | affected / debian | ausente | sistema |
| F209 | libuuid1 @ 2.41.5-0+deb13u1 | util-linux @ 2.41.5-0+deb13u1 | ausente | HIGH / ausente | affected / debian | ausente | sistema |
| F210 | login @ 1:4.16.0-2+really2.41.5-0+deb13u1 | util-linux @ 2.41.5-0+deb13u1 | ausente | HIGH / ausente | affected / debian | ausente | sistema |
| F211 | mount @ 2.41.5-0+deb13u1 | util-linux @ 2.41.5-0+deb13u1 | ausente | HIGH / ausente | affected / debian | ausente | sistema |
| F212 | util-linux @ 2.41.5-0+deb13u1 | util-linux @ 2.41.5-0+deb13u1 | ausente | HIGH / ausente | affected / debian | ausente | sistema |

Introductor y origen por fila:

- **F204:** Base Python/Debian (inferencia por capa); introductor concreto no identificado. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DiffID observado, sin inventar una arista de dependencia. Regresiones: OS.
- **F205:** APT CI explícito: ffmpeg → libavcodec61 → libglib2.0-0t64 → libmount1 → libblkid1. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F206:** Base Python/Debian (inferencia por capa); introductor concreto no identificado. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DiffID observado, sin inventar una arista de dependencia. Regresiones: OS.
- **F207:** APT CI explícito: ffmpeg → libavcodec61 → libglib2.0-0t64 → libmount1. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F208:** Base Python/Debian (inferencia por capa); introductor concreto no identificado. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DiffID observado, sin inventar una arista de dependencia. Regresiones: OS.
- **F209:** Base Python/Debian (inferencia por capa); introductor concreto no identificado. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DiffID observado, sin inventar una arista de dependencia. Regresiones: OS.
- **F210:** Base Python/Debian (inferencia por capa); introductor concreto no identificado. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DiffID observado, sin inventar una arista de dependencia. Regresiones: OS.
- **F211:** Base Python/Debian (inferencia por capa); introductor concreto no identificado. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DiffID observado, sin inventar una arista de dependencia. Regresiones: OS.
- **F212:** Base Python/Debian (inferencia por capa); introductor concreto no identificado. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DiffID observado, sin inventar una arista de dependencia. Regresiones: OS.

### CVE-2026-78410 — util-linux (9 hallazgos)

Fuente verificada: [Debian Security Tracker](https://security-tracker.debian.org/tracker/CVE-2026-78410); consulta `2026-11-10T01:23:38.2797542Z`. Estado: **open**; fixed aplicable: **ausente**.

Corrección mínima: Bloqueado: Debian trixie mantiene util-linux/CVE-2026-78410 abierto y no publica fixed_version para esta suite. Ningún pin corregido respaldado; no usar sid/forky ni declarar remediado por actualizar el snapshot.

Repositorios de trixie observados: {"trixie": "2.41.5-0+deb13u1", "trixie-security": "2.41.5-0+deb13u1"}.

| ID | Paquete binario @ instalada | Source @ versión | SrcName crudo | Severidad / SeveritySource | Status / DataSource.ID | FixedVersion crudo | Ámbito |
|---|---|---|---|---|---|---|---|
| F213 | bsdutils @ 1:2.41.5-0+deb13u1 | util-linux @ 2.41.5-0+deb13u1 | ausente | HIGH / ausente | affected / debian | ausente | sistema |
| F214 | libblkid1 @ 2.41.5-0+deb13u1 | util-linux @ 2.41.5-0+deb13u1 | ausente | HIGH / ausente | affected / debian | ausente | sistema |
| F215 | liblastlog2-2 @ 2.41.5-0+deb13u1 | util-linux @ 2.41.5-0+deb13u1 | ausente | HIGH / ausente | affected / debian | ausente | sistema |
| F216 | libmount1 @ 2.41.5-0+deb13u1 | util-linux @ 2.41.5-0+deb13u1 | ausente | HIGH / ausente | affected / debian | ausente | sistema |
| F217 | libsmartcols1 @ 2.41.5-0+deb13u1 | util-linux @ 2.41.5-0+deb13u1 | ausente | HIGH / ausente | affected / debian | ausente | sistema |
| F218 | libuuid1 @ 2.41.5-0+deb13u1 | util-linux @ 2.41.5-0+deb13u1 | ausente | HIGH / ausente | affected / debian | ausente | sistema |
| F219 | login @ 1:4.16.0-2+really2.41.5-0+deb13u1 | util-linux @ 2.41.5-0+deb13u1 | ausente | HIGH / ausente | affected / debian | ausente | sistema |
| F220 | mount @ 2.41.5-0+deb13u1 | util-linux @ 2.41.5-0+deb13u1 | ausente | HIGH / ausente | affected / debian | ausente | sistema |
| F221 | util-linux @ 2.41.5-0+deb13u1 | util-linux @ 2.41.5-0+deb13u1 | ausente | HIGH / ausente | affected / debian | ausente | sistema |

Introductor y origen por fila:

- **F213:** Base Python/Debian (inferencia por capa); introductor concreto no identificado. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DiffID observado, sin inventar una arista de dependencia. Regresiones: OS.
- **F214:** APT CI explícito: ffmpeg → libavcodec61 → libglib2.0-0t64 → libmount1 → libblkid1. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F215:** Base Python/Debian (inferencia por capa); introductor concreto no identificado. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DiffID observado, sin inventar una arista de dependencia. Regresiones: OS.
- **F216:** APT CI explícito: ffmpeg → libavcodec61 → libglib2.0-0t64 → libmount1. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F217:** Base Python/Debian (inferencia por capa); introductor concreto no identificado. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DiffID observado, sin inventar una arista de dependencia. Regresiones: OS.
- **F218:** Base Python/Debian (inferencia por capa); introductor concreto no identificado. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DiffID observado, sin inventar una arista de dependencia. Regresiones: OS.
- **F219:** Base Python/Debian (inferencia por capa); introductor concreto no identificado. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DiffID observado, sin inventar una arista de dependencia. Regresiones: OS.
- **F220:** Base Python/Debian (inferencia por capa); introductor concreto no identificado. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DiffID observado, sin inventar una arista de dependencia. Regresiones: OS.
- **F221:** Base Python/Debian (inferencia por capa); introductor concreto no identificado. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DiffID observado, sin inventar una arista de dependencia. Regresiones: OS.

### CVE-2026-85091 — zlib (1 hallazgos)

Fuente verificada: [Debian Security Tracker](https://security-tracker.debian.org/tracker/CVE-2026-85091); consulta `2026-11-10T01:23:38.2797542Z`. Estado: **resolved**; fixed aplicable: **1:1.3.dfsg+really1.3.1-1+deb13u1**.

Corrección mínima: Candidato de backport trixie: zlib 1:1.3.dfsg+really1.3.1-1+deb13u1; verificar binario exacto en APT del snapshot aprobado e instalar solo los paquetes necesarios. No ejecutado.

Repositorios de trixie observados: {"trixie": "1:1.3.dfsg+really1.3.1-1", "trixie-security": "1:1.3.dfsg+really1.3.1-1+deb13u1"}.

| ID | Paquete binario @ instalada | Source @ versión | SrcName crudo | Severidad / SeveritySource | Status / DataSource.ID | FixedVersion crudo | Ámbito |
|---|---|---|---|---|---|---|---|
| F222 | zlib1g @ 1:1.3.dfsg+really1.3.1-1+b1 | zlib @ 1:1.3.dfsg+really1.3.1-1 | ausente | HIGH / ausente | fixed / debian | 1:1.3.dfsg+really1.3.1-1+deb13u1 | sistema |

Introductor y origen por fila:

- **F222:** APT CI explícito: ffmpeg → libavcodec61 → zlib1g. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.

### CVE-2026-86138 — libxml2 (1 hallazgos)

Fuente verificada: [Debian Security Tracker](https://security-tracker.debian.org/tracker/CVE-2026-86138); consulta `2026-11-10T01:23:38.2797542Z`. Estado: **open**; fixed aplicable: **ausente**.

Corrección mínima: Bloqueado: Debian trixie mantiene libxml2/CVE-2026-86138 abierto y no publica fixed_version para esta suite. Ningún pin corregido respaldado; no usar sid/forky ni declarar remediado por actualizar el snapshot.

Repositorios de trixie observados: {"trixie": "2.12.7+dfsg+really2.9.14-2.1+deb13u3", "trixie-security": "2.12.7+dfsg+really2.9.14-2.1+deb13u1"}.

| ID | Paquete binario @ instalada | Source @ versión | SrcName crudo | Severidad / SeveritySource | Status / DataSource.ID | FixedVersion crudo | Ámbito |
|---|---|---|---|---|---|---|---|
| F223 | libxml2 @ 2.12.7+dfsg+really2.9.14-2.1+deb13u3 | libxml2 @ 2.12.7+dfsg+really2.9.14-2.1+deb13u3 | ausente | HIGH / nvd | affected / debian | ausente | sistema |

Introductor y origen por fila:

- **F223:** APT CI explícito: ffmpeg → libavformat61 → libxml2. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.

### CVE-2026-86139 — libxml2 (1 hallazgos)

Fuente verificada: [Debian Security Tracker](https://security-tracker.debian.org/tracker/CVE-2026-86139); consulta `2026-11-10T01:23:38.2797542Z`. Estado: **open**; fixed aplicable: **ausente**.

Corrección mínima: Bloqueado: Debian trixie mantiene libxml2/CVE-2026-86139 abierto y no publica fixed_version para esta suite. Ningún pin corregido respaldado; no usar sid/forky ni declarar remediado por actualizar el snapshot.

Repositorios de trixie observados: {"trixie": "2.12.7+dfsg+really2.9.14-2.1+deb13u3", "trixie-security": "2.12.7+dfsg+really2.9.14-2.1+deb13u1"}.

| ID | Paquete binario @ instalada | Source @ versión | SrcName crudo | Severidad / SeveritySource | Status / DataSource.ID | FixedVersion crudo | Ámbito |
|---|---|---|---|---|---|---|---|
| F224 | libxml2 @ 2.12.7+dfsg+really2.9.14-2.1+deb13u3 | libxml2 @ 2.12.7+dfsg+really2.9.14-2.1+deb13u3 | ausente | HIGH / nvd | affected / debian | ausente | sistema |

Introductor y origen por fila:

- **F224:** APT CI explícito: ffmpeg → libavformat61 → libxml2. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.

### CVE-2026-86140 — libxml2 (1 hallazgos)

Fuente verificada: [Debian Security Tracker](https://security-tracker.debian.org/tracker/CVE-2026-86140); consulta `2026-11-10T01:23:38.2797542Z`. Estado: **open**; fixed aplicable: **ausente**.

Corrección mínima: Bloqueado: Debian trixie mantiene libxml2/CVE-2026-86140 abierto y no publica fixed_version para esta suite. Ningún pin corregido respaldado; no usar sid/forky ni declarar remediado por actualizar el snapshot.

Repositorios de trixie observados: {"trixie": "2.12.7+dfsg+really2.9.14-2.1+deb13u3", "trixie-security": "2.12.7+dfsg+really2.9.14-2.1+deb13u1"}.

| ID | Paquete binario @ instalada | Source @ versión | SrcName crudo | Severidad / SeveritySource | Status / DataSource.ID | FixedVersion crudo | Ámbito |
|---|---|---|---|---|---|---|---|
| F225 | libxml2 @ 2.12.7+dfsg+really2.9.14-2.1+deb13u3 | libxml2 @ 2.12.7+dfsg+really2.9.14-2.1+deb13u3 | ausente | HIGH / nvd | affected / debian | ausente | sistema |

Introductor y origen por fila:

- **F225:** APT CI explícito: ffmpeg → libavformat61 → libxml2. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.

### CVE-2026-86142 — libxml2 (1 hallazgos)

Fuente verificada: [Debian Security Tracker](https://security-tracker.debian.org/tracker/CVE-2026-86142); consulta `2026-11-10T01:23:38.2797542Z`. Estado: **open**; fixed aplicable: **ausente**.

Corrección mínima: Bloqueado: Debian trixie mantiene libxml2/CVE-2026-86142 abierto y no publica fixed_version para esta suite. Ningún pin corregido respaldado; no usar sid/forky ni declarar remediado por actualizar el snapshot.

Repositorios de trixie observados: {"trixie": "2.12.7+dfsg+really2.9.14-2.1+deb13u3", "trixie-security": "2.12.7+dfsg+really2.9.14-2.1+deb13u1"}.

| ID | Paquete binario @ instalada | Source @ versión | SrcName crudo | Severidad / SeveritySource | Status / DataSource.ID | FixedVersion crudo | Ámbito |
|---|---|---|---|---|---|---|---|
| F226 | libxml2 @ 2.12.7+dfsg+really2.9.14-2.1+deb13u3 | libxml2 @ 2.12.7+dfsg+really2.9.14-2.1+deb13u3 | ausente | HIGH / nvd | affected / debian | ausente | sistema |

Introductor y origen por fila:

- **F226:** APT CI explícito: ffmpeg → libavformat61 → libxml2. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.

### CVE-2026-86143 — libxml2 (1 hallazgos)

Fuente verificada: [Debian Security Tracker](https://security-tracker.debian.org/tracker/CVE-2026-86143); consulta `2026-11-10T01:23:38.2797542Z`. Estado: **open**; fixed aplicable: **ausente**.

Corrección mínima: Bloqueado: Debian trixie mantiene libxml2/CVE-2026-86143 abierto y no publica fixed_version para esta suite. Ningún pin corregido respaldado; no usar sid/forky ni declarar remediado por actualizar el snapshot.

Repositorios de trixie observados: {"trixie": "2.12.7+dfsg+really2.9.14-2.1+deb13u3", "trixie-security": "2.12.7+dfsg+really2.9.14-2.1+deb13u1"}.

| ID | Paquete binario @ instalada | Source @ versión | SrcName crudo | Severidad / SeveritySource | Status / DataSource.ID | FixedVersion crudo | Ámbito |
|---|---|---|---|---|---|---|---|
| F227 | libxml2 @ 2.12.7+dfsg+really2.9.14-2.1+deb13u3 | libxml2 @ 2.12.7+dfsg+really2.9.14-2.1+deb13u3 | ausente | HIGH / nvd | affected / debian | ausente | sistema |

Introductor y origen por fila:

- **F227:** APT CI explícito: ffmpeg → libavformat61 → libxml2. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.

### CVE-2026-86144 — libxml2 (1 hallazgos)

Fuente verificada: [Debian Security Tracker](https://security-tracker.debian.org/tracker/CVE-2026-86144); consulta `2026-11-10T01:23:38.2797542Z`. Estado: **open**; fixed aplicable: **ausente**.

Corrección mínima: Bloqueado: Debian trixie mantiene libxml2/CVE-2026-86144 abierto y no publica fixed_version para esta suite. Ningún pin corregido respaldado; no usar sid/forky ni declarar remediado por actualizar el snapshot.

Repositorios de trixie observados: {"trixie": "2.12.7+dfsg+really2.9.14-2.1+deb13u3", "trixie-security": "2.12.7+dfsg+really2.9.14-2.1+deb13u1"}.

| ID | Paquete binario @ instalada | Source @ versión | SrcName crudo | Severidad / SeveritySource | Status / DataSource.ID | FixedVersion crudo | Ámbito |
|---|---|---|---|---|---|---|---|
| F228 | libxml2 @ 2.12.7+dfsg+really2.9.14-2.1+deb13u3 | libxml2 @ 2.12.7+dfsg+really2.9.14-2.1+deb13u3 | ausente | HIGH / nvd | affected / debian | ausente | sistema |

Introductor y origen por fila:

- **F228:** APT CI explícito: ffmpeg → libavformat61 → libxml2. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.

### CVE-2026-87933 — cjson (1 hallazgos)

Fuente verificada: [Debian Security Tracker](https://security-tracker.debian.org/tracker/CVE-2026-87933); consulta `2026-11-10T01:23:38.2797542Z`. Estado: **open**; fixed aplicable: **ausente**.

Corrección mínima: Bloqueado: Debian trixie mantiene cjson/CVE-2026-87933 abierto y no publica fixed_version para esta suite. Ningún pin corregido respaldado; no usar sid/forky ni declarar remediado por actualizar el snapshot.

Repositorios de trixie observados: {"trixie": "1.7.18-3.1+deb13u1", "trixie-security": "1.7.18-3.1+deb13u1"}.

| ID | Paquete binario @ instalada | Source @ versión | SrcName crudo | Severidad / SeveritySource | Status / DataSource.ID | FixedVersion crudo | Ámbito |
|---|---|---|---|---|---|---|---|
| F229 | libcjson1 @ 1.7.18-3.1+deb13u1 | cjson @ 1.7.18-3.1+deb13u1 | ausente | HIGH / ausente | affected / debian | ausente | sistema |

Introductor y origen por fila:

- **F229:** APT CI explícito: ffmpeg → libavformat61 → librist4 → libcjson1. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.

### CVE-2026-88806 — libx11 (3 hallazgos)

Fuente verificada: [Debian Security Tracker](https://security-tracker.debian.org/tracker/CVE-2026-88806); consulta `2026-11-10T01:23:38.2797542Z`. Estado: **open**; fixed aplicable: **ausente**.

Corrección mínima: Bloqueado: Debian trixie mantiene libx11/CVE-2026-88806 abierto y no publica fixed_version para esta suite. Ningún pin corregido respaldado; no usar sid/forky ni declarar remediado por actualizar el snapshot.

Repositorios de trixie observados: {"trixie": "2:1.8.12-1"}.

| ID | Paquete binario @ instalada | Source @ versión | SrcName crudo | Severidad / SeveritySource | Status / DataSource.ID | FixedVersion crudo | Ámbito |
|---|---|---|---|---|---|---|---|
| F230 | libx11-6 @ 2:1.8.12-1 | libx11 @ 2:1.8.12-1 | ausente | HIGH / ausente | affected / debian | ausente | sistema |
| F231 | libx11-data @ 2:1.8.12-1 | libx11 @ 2:1.8.12-1 | ausente | HIGH / ausente | affected / debian | ausente | sistema |
| F232 | libx11-xcb1 @ 2:1.8.12-1 | libx11 @ 2:1.8.12-1 | ausente | HIGH / ausente | affected / debian | ausente | sistema |

Introductor y origen por fila:

- **F230:** APT CI explícito: ffmpeg → libavdevice61 → libx11-6. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F231:** APT CI explícito: ffmpeg → libavdevice61 → libx11-6 → libx11-data. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.
- **F232:** APT CI explícito: ffmpeg → libavdevice61 → libpulse0 → libx11-xcb1. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.

### CVE-2026-88807 — libxrender (1 hallazgos)

Fuente verificada: [Debian Security Tracker](https://security-tracker.debian.org/tracker/CVE-2026-88807); consulta `2026-11-10T01:23:38.2797542Z`. Estado: **open**; fixed aplicable: **ausente**.

Corrección mínima: Bloqueado: Debian trixie mantiene libxrender/CVE-2026-88807 abierto y no publica fixed_version para esta suite. Ningún pin corregido respaldado; no usar sid/forky ni declarar remediado por actualizar el snapshot.

Repositorios de trixie observados: {"trixie": "1:0.9.12-1"}.

| ID | Paquete binario @ instalada | Source @ versión | SrcName crudo | Severidad / SeveritySource | Status / DataSource.ID | FixedVersion crudo | Ámbito |
|---|---|---|---|---|---|---|---|
| F233 | libxrender1 @ 1:0.9.12-1 | libxrender @ 1:0.9.12-1 | ausente | HIGH / ausente | affected / debian | ausente | sistema |

Introductor y origen por fila:

- **F233:** APT CI explícito: ffmpeg → libavcodec61 → libcairo2 → libxrender1. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DependsOn de Results.Packages; raíces APT ffmpeg/fonts-dejavu-core declaradas en Dockerfile.ci. Regresiones: OS, MEDIA.

### CVE-2026-9538 — perl (1 hallazgos)

Fuente verificada: [Debian Security Tracker](https://security-tracker.debian.org/tracker/CVE-2026-9538); consulta `2026-11-10T01:23:38.2797542Z`. Estado: **open**; fixed aplicable: **ausente**.

Corrección mínima: Bloqueado: Debian trixie mantiene perl/CVE-2026-9538 abierto y no publica fixed_version para esta suite. Ningún pin corregido respaldado; no usar sid/forky ni declarar remediado por actualizar el snapshot.

Repositorios de trixie observados: {"trixie": "5.40.1-6+deb13u1"}.

| ID | Paquete binario @ instalada | Source @ versión | SrcName crudo | Severidad / SeveritySource | Status / DataSource.ID | FixedVersion crudo | Ámbito |
|---|---|---|---|---|---|---|---|
| F234 | perl-base @ 5.40.1-6+deb13u1 | perl @ 5.40.1-6+deb13u1 | ausente | HIGH / nvd | fix_deferred / debian | ausente | sistema |

Introductor y origen por fila:

- **F234:** Base Python/Debian (inferencia por capa); introductor concreto no identificado. Origen: Debian 13.7/trixie; dpkg de imagen CI. Evidencia: DiffID observado, sin inventar una arista de dependencia. Regresiones: OS.

