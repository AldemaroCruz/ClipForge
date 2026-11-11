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
