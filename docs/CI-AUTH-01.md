# CI-AUTH-01: integración de autenticación con PostgreSQL real

La entrega AUTH-01 revisada se conserva como commit específico. Su patch
`ad0bdbc752e60e2a17bd16646ddeb85057619e79ab56ab07c8336e5726d42ec7` contiene
37 archivos modificados y 24 nuevos; no tenía diferencias posteriores al comenzar.
La integración se versiona aparte. SEC-05, la candidata de desarrollo, sus
cuentas/volúmenes/estado externo y la instalación operativa quedan fuera.
No hay recuperación de cuentas, cambio de distribución, Pro/ESM o servicios nuevos.

## Ejecución y límites

El workflow prepara fuentes permitidas con manifiesto verificado. Descarga las
imágenes y la DB Trivy durante preparación; después usa identidades inmutables.
`scripts/ci_postgres.py` crea una red interna y PostgreSQL efímero por ejecución.
El puerto PostgreSQL no se publica; no hay montajes de la raíz ni socket en los
contenedores de pruebas. Contraseñas nuevas se generan en scratch privado fuera
de reportes, sin pasarlas por argv, logs, connection strings o variables públicas.
La aplicación usa un rol propio; las migraciones reales se ejecutan antes de tests.

PostgreSQL almacena sus datos en tmpfs de esa ejecución, con UID/GID explícitos
del runner. Los demás escritores de scratch mantienen CI-FIX-01: identidad
explícita, raíz de contenedor RO, capabilities retiradas y NNP; sin chmod777 ni
permisos adicionales. La suite y los navegadores usan la red **internal** propia:
se comprueban PostgreSQL alcanzable, ausencia de puertos y salida externa bloqueada.
Inventarios y scanners siguen usando `--network none`.

La limpieza verifica nombres, etiquetas e identidades antes de retirar únicamente
contenedores/red de la ejecución, incluidos tests que sigan activos; borra solo
los tres archivos privados generados. Hay manejo de interrupción y paso
`if: always()` tras los tests, con cierre idempotente adicional antes del gate y
subida de artefactos. No usa prune ni toca volúmenes
de la candidata. El informe de limpieza se exige como evidencia, con fecha posterior
al de aislamiento. Una caída forzada del runner puede impedir cualquier cleanup
de usuario; el runner hospedado es efímero y no se promete haber probado tal caída.
Semántica de cancelación: [documentación oficial de GitHub](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-cancellation).

## Contratos de prueba y seguridad

Se conserva discovery, listado/hash de IDs, comparación con ejecución, cobertura,
checks nativos y rechazo de omisiones. El antecedente de 612 tests no es un umbral
fijo: el informe real enumera las incorporaciones de esta integración.
Los seis escenarios anteriores siguen separados: cinco HTTP real y smoke con fetch
simulado. `run_ci_auth_browser.py` añade `browser_auth.py` sobre PostgreSQL real y
registra siete pasos únicos: login, creación administrativa, sesiones independientes,
reinicio, revocación por contraseña, desactivación y logout/móvil. No genera traces,
HAR, cookies, storage state o dumps. El wrapper no acredita un reporte aparentemente
correcto si el proceso falla o agota su tiempo.

El gate exige AUTH completo, HTTP/PostgreSQL reales, autenticación no simulada,
identidades de ambas imágenes y hash del manifiesto. Los tests negativos cubren
ausencia, parcialidad, fallo, simulación, duplicados e identidades incorrectas.
Las nuevas fixtures del contrato no se presentan como ejecución real del navegador.
Se comprueba sintaxis de los cuatro JavaScript, incluidos auth y account.

PostgreSQL recibe inventario independiente, archivo de imagen con SHA-256,
SBOM y reporte Trivy propios. Se comprueban los paquetes OS y componentes
adicionales reales; no se le exigen artificialmente Python/Node. SAST/SCA conservan
reglas y umbrales, sin supresiones ni aceptación de findings. El validador distingue
`security_finding` de errores de evidencia/ejecución; ambos bloquean el gate.
Los reportes históricos no acreditan las nuevas imágenes.

Solo se sube el directorio de informes permitido. El estado privado del helper,
claves, archivos de base y archivos tar de imágenes quedan fuera. La selección Git
es explícita y se escanea un snapshot de los blobs exactos del índice antes de cada
commit, sin `git add .`. Solo se autoriza push normal a `ci/bootstrap-sec03`.

## Resultados de la entrega

AUTH-01: commit `7a3573f10068af07e4c5e3a062e82396cc440b24`, 61 archivos,
157 blobs de índice escaneados sin hallazgos. No se incorporó SEC-05.

Validación local de CI-AUTH-01 sobre imágenes nuevas:

| Control | Resultado registrado |
| --- | --- |
| Build CI / browser | Ambos salida 0; manifiesto verificado antes/después |
| Suite / checks nativos | 681 tests, 0 fallos/errores/skips; 11 checks aprobados |
| Inventario | 612 IDs anteriores conservados; 69 añadidos, ninguno retirado |
| Nuevos tests | 9 wrapper AUTH, 18 lifecycle PostgreSQL, 23 validador, 19 inventario PostgreSQL/Go |
| Browser previo | 6 aprobados: 5 HTTP real, 1 fetch simulado |
| Browser AUTH | 7 pasos aprobados, PostgreSQL real y reinicio de proceso |
| Aislamiento | Internal=true, PG sin puertos, rol no superuser/createdb, sin ruta IPv4 por defecto, dos TCP externos bloqueados |
| Migración y limpieza | Migración salida 0; cierre real e idempotencia salida 0, sin recursos propios remanentes |
| JavaScript | Sintaxis de cuatro archivos aprobada |
| Workflow | actionlint salida 0; fixture inválida rechazada con salida 1 |
| SAST | Salida 1; 39 findings: 36 LOW y 3 MEDIUM; sin errores de scanner ni supresiones |
| PostgreSQL SCA | Salida 1 por 147 HIGH y 2 CRITICAL: 123 findings OS y 26 en gosu/Go; SBOM salida 0 |

Imágenes locales:

```text
CI      sha256:d5c7d80b805b8bc452b18c61c220ee97a705c26c805c256927339945409167ff
browser sha256:6ca6c6fecc3d1fdac9df52f30bd162916a910ba971958f405ba5cef7ed225f55
PG      sha256:8bca9649e52d948114ccc8164b55b7ab26b64e729893e420114bb5c87bf7c7cc
```

Los SCA de aplicación/browser tienen reportes propios vinculados a esos ImageID.
No se infiere su estado de los scans históricos. Los resultados finales del gate
local y de Actions se conservan por intento, sin aprobar release ni aceptar riesgos.
El registro histórico mantiene su alcance; los findings CI-AUTH-01 son nuevas
observaciones no aceptadas en sus informes de SAST/SCA.

Incidencias locales preservadas: el primer download de DB Trivy usó temporal256MiB
y falló por espacio; se corrigió a512MiB, como el workflow. El primer SCA browser
local compitió por la caché filesystem con CI y falló sin emitir reportes; solo ese
análisis incompleto se repitió con caché separada y la misma DB verificada. El
workflow ejecuta scans secuencialmente. Ningún caso se presentó como CVE ni borró
el intento fallido. La cancelación se cubre con fixtures del contrato; no se
afirma haber cancelado deliberadamente un run de GitHub o matado su runner.

Expediente nuevo: `.ci-local/ci-auth01-5fd6be89/`. Conserva el estado inicial,
comparación con el patch revisado, commits, regresiones, contextos, builds y cada
intento con su código. Los resultados y el enlace al run se incorporan al cierre;
la mera presencia del workflow no declara validado GitHub Actions ni aprueba release.

## Cierre observado en GitHub: run 42947739289

Revisión de artefactos el 2026-11-11. Commit
`7fe3a486911c281c58fb7de3df72ad87f2c696e9`, rama `ci/bootstrap-sec03`,
[run 42947739289](https://github.com/AldemaroCruz/ClipForge/actions/runs/42947739289).
Se reutilizó `clipforge-ci-42947739289-1`, ya descargado en
`.ci-local/ci-auth01-5fd6be89/github-artifacts-42947739289-1/`.
Los 203 archivos coinciden con el manifiesto previo en nombres, bytes y SHA256;
no se descargaron nuevamente ni se repitieron builds, tests o scanners.

**Integración funcional comprobada en GitHub; CI global rechazado por seguridad.**
El validador final contiene exactamente cuatro errores `security_finding`:
`bandit`, `trivy`, `browser-trivy`, `postgres_trivy`. No contiene errores de
identidad, integridad, esquema, ejecución, omisión o limpieza. El job CI Gate
también falla al propagar esos rechazos; no es otro defecto de integración.

### Discovery, regresiones y aceptación

- **681 IDs descubiertos, únicos y ejecutados**, cero duplicados, fallos,
  errores, skips, expected failures o unexpected successes. El check de
  completeness y las listas reales concuerdan; no se usa el contador como
  sustituto del inventario. SHA256 de IDs UTF8/LF:
  `1d7d3ba67a46dadd6ea1edbd66e4fa68cf2425da1a2cb4d07c169f2f271068fd`.
- Se conservan los **612 IDs de AUTH-01**, sin retirados. Las **69 altas** son
  9 de `test_ci_auth_browser`, 18 de `test_ci_postgres`, 23 de `test_ci_reports`
  y 19 de `test_postgres_inventory`. Son tests de integración y contratos CI;
  las fixtures negativas de scanner/validador no se presentan como fallos reales.
- Pasan los **11 checks**: isolated_environment, ffmpeg, ffprobe, pip_check,
  runtime, media, presentation, branding, test_inventory,
  test_execution_completeness y coverage.
- Pasan los seis escenarios previos: **smoke** (`simulated_fetch`) y
  **workflow, editorial, delivery, ai y operations** (HTTP directo). Todos
  tienen exit0, sin timeout ni bridge. Los 60 pasos reportados no son 60 tests
  unitarios ni se suman a 681. ASR/LLM siguen siendo fixtures.
- AUTH adicional: **siete pasos aprobados**, HTTP directo, PostgreSQL real,
  `auth_mocked=false` y reinicio real del proceso Uvicorn: login,
  admin_create_user, independent_sessions, process_restart, password_revocation,
  admin_deactivation y logout_mobile. No son siete IDs unitarios adicionales.
- Migración real, suite, browser y auth-browser registran salida0. La red
  Docker propia es **internal**, sin salida externa, con PostgreSQL sin puerto
  publicado y rol de aplicación sin privilegios de superusuario/createdb.
  No se describe esa integración como `--network none`.

Cobertura Coverage 7.17.2, 49 archivos `app/` y `scripts/`, sin omit ni líneas
excluidas: **líneas 5125/6288 = 81,50445292620866 %; ramas 1278/1790 =
71,39664804469274 %; combinada 79,26466947264174 %**. Mide el proceso unittest
con mocks/threads explícitos; excluye navegador, AUTH/PostgreSQL en otros procesos
y subprocesos de checks nativos. No se inventó un umbral. Por ejemplo,
`scripts/auth_migrate.py` tiene cero cobertura en ese proceso; eso no contradice
la migración real separada con exit0.

### Seguridad real del mismo run

Bandit 1.9.4: **39 findings, 36 LOW y 3 MEDIUM; cero errores**, 7950 LOC,
49 archivos, nosec0 y skipped_tests0. Reglas: **B404=15, B603=20, B108=3,
B105=1**. Las tres MEDIUM son B108 en `scripts/ci_postgres.py:227,295,302`;
no se aceptan ni se clasifican automáticamente como falsos positivos.

| Imagen | HIGH | CRITICAL | IDs únicos | Paquetes inventariados / componentes SBOM |
| --- | ---: | ---: | ---: | --- |
| CI | 281 | 1 | 66 | 349 / 350 |
| Browser | 283 | 1 | 68 | 361 / 362 |
| PostgreSQL | 147 | 2 | 62 | 149 / 151 |

Son **715 filas y 97 IDs distintos en la unión**, no 196 CVEs únicos.
Los informes son H/C; no acreditan ausencia de otros niveles. En CI/browser,
todos esos findings pertenecen a paquetes OS; los targets Python56 y Node1
permanecen presentes, sin findings H/C en este filtro. Las principales
concentraciones por source son FFmpeg153, krb556 y util-linux36 filas en cada
imagen de aplicación; browser añade dos de CUPS. Matriz completa por paquete,
versión, fuente y SeveritySource en el expediente de cierre.

PostgreSQL se desglosa expresamente:

- Motor **18.6**, paquete `postgresql-18=18.6-1.pgdg13+2`, binario inventariado,
  perteneciente al paquete e incluido en SBOM; cero findings atribuidos al motor
  en estos JSON, sin afirmar que esté libre de vulnerabilidades.
- Sistema Debian: **145 paquetes**, **122 HIGH + 1 CRITICAL**, 36 IDs únicos.
  Incluye krb5, util-linux, libxml2, gnupg2, ncurses, perl, sqlite3 y otros.
- `/usr/local/bin/gosu` **1.19**, módulo principal v1.19.0, con Go **1.24.6**:
  cuatro componentes reales, **25 HIGH + 1 CRITICAL**, 26 IDs en stdlib embebida.
  No son vulnerabilidades atribuidas al servidor SQL. No se inventan targets
  Python/Node para esta imagen. Su SBOM tiene 149 libraries, un OS y una
  application; el informe registra SCA exit1 por findings y SBOM exit0.

CRITICAL: las tres imágenes contienen **CVE-2026-6653** en
`libxml2=2.12.7+dfsg+really2.9.14-2.1+deb13u3`, SeveritySource nvd,
DataSource Debian, estado affected y FixedVersion ausente. PostgreSQL contiene
además **CVE-2025-68121**, Go `stdlib v1.24.6` de gosu, SeveritySource nvd y
DataSource Go. Su `Status=fixed` significa fix catalogado
`1.24.13, 1.25.7, 1.26.0-rc.3`, no instalado. No se inicia aquí remediación ni
verificación general de fixes; se conserva la evidencia original.

Identidades reales, concordantes entre archivos ID, inventario, Trivy y SBOM:

```text
CI      sha256:ef2a2c36f0a7214992b545b06b72ec4136f14cd07f64f72b28e733d0fd72990a
browser sha256:d732173631c8867e92abd65e762feef2ba127b9553a27ea3c443240200f9f02b
PG      sha256:8bca9649e52d948114ccc8164b55b7ab26b64e729893e420114bb5c87bf7c7cc
```

Trivy **0.76.2**, DB schema2, SHA256
`cf7fa3086682e8f77298ca8178419a530f97d7c4bd3ac203a64f2977f82e94a6`;
UpdatedAt `2026-11-10T19:01:23.081219346Z`, DownloadedAt
`2026-11-11T02:41:54.100579649Z`, NextUpdate
`2026-11-11T19:01:23.081218965Z`. Son metadatos/hash compartidos registrados por
el run y concordantes con Trivy-version; cada JSON de imagen no contiene una
huella DB individual. SeveritySource ausente se conserva ausente, sin inferirlo
desde DataSource. Los TAR y el payload DB no están adjuntos: se verificaron las
declaraciones de sus hashes contra el manifiesto, sin recalcular esos payloads.
Gitleaks del run registra cero findings sobre 164 fuentes;
sus hashes coinciden con los blobs del SHA que disparó Actions. Esto no es un
nuevo escaneo de la documentación modificada en este cierre.

### Limpieza, conservación y decisiones

Los reportes de limpieza principal e idempotente indican `clean`, propiedad
verificada, sin contenedores/redes propios ni archivos privados restantes.
Se retiraron únicamente los recursos identificados de esa ejecución. El job
conservó reportes y retiró su scratch de scanner, ambos con resultado success.
No se ejecutó una nueva consulta Docker contra recursos del propietario.
Los 203 archivos del bundle siguen byteidénticos al manifiesto de descarga;
su inventario de nombres no incluye dumps, archivos privados del lanzador,
cookies, tokens ni TARs. No se ejecutó otro scanner de secretos sobre reportes.
No se publican logs privados, connection strings o variables de contenedor.

El [registro de riesgos](RISK-REGISTER.md) añade 715 SCA y 39 SAST con sus fuentes,
identidades y severidades originales. Conserva las 4.717 observaciones previas
y ambos intentos SAST AUTH-01; ninguna aceptación, supresión o cambio de política.
El cierre modifica solamente esta documentación y el registro; no incluye los
experimentos SEC-05 preexistentes. Pro/ESM aplazado y presupuesto de servicios
nuevos cero. Sin commit/push, dependencias, distribución, lógica AUTH o cambios
operativos; release/despliegue siguen bloqueados.

Expediente de revisión: `.ci-local/ci-auth01-close-038d6d04/`, con
[QA](../.ci-local/ci-auth01-close-038d6d04/qa/REPORT.md),
[seguridad y matriz](../.ci-local/ci-auth01-close-038d6d04/security/analysis-1/review.md),
[infraestructura](../.ci-local/ci-auth01-close-038d6d04/infra/report.md), delta de
riesgos y hashes. **No se identifica otro
fallo de integración además de los cuatro bloqueos de seguridad** en la evidencia
conservada de este run. No se reabre SEC-05 ni se implementan recuperación local
de cuentas o auditoría de acciones en este cierre.
