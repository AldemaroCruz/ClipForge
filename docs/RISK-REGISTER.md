# Registro de riesgos de desarrollo local

Decisión del propietario, 2026-11-10: AUTH-01 puede desarrollarse y probarse
localmente sin aceptar los riesgos pendientes. Presupuesto de servicios nuevos
cero; Pro/ESM aplazado. Publicación, release y despliegue siguen bloqueados.

El [registro estructurado](risk-register.json) conserva cada observación real
de los seis informes históricos de SEC-05, todas las severidades y las 28
ubicaciones SAST de SEC-04/GitHub. Incluye componente/versión, severidad y fuente
original, imagen o huellas de archivo/span, referencia/hash de evidencia,
exposición, estado, mitigación, responsable, revisión y aceptación/expiración.
No se reemplazaron severidades ni se completó una fuente ausente por inferencia.

| Evidencia histórica | Observaciones de todos los niveles | HIGH | CRITICAL |
| --- | ---: | ---: | ---: |
| Trixie baseline CI | 895 | 281 | 1 |
| Trixie baseline browser | 950 | 283 | 1 |
| Noble inicial CI | 707 | 2 | 0 |
| Noble inicial browser | 717 | 2 | 0 |
| Noble aptfix histórico CI | 705 | 0 | 0 |
| Noble aptfix histórico browser | 715 | 0 | 0 |
| SAST histórico por ubicación | 28 LOW: 12 B404 y 16 B603 | 0 | 0 |

Son 4.689 observaciones paquete/CVE/imagen, no CVEs únicos. Se preservan también
las observaciones de APT presentes antes del fix; no se borran por existir una
imagen posterior. `FixedVersion` indica un fix catalogado, no aplicado.
Menor severidad o ausencia en otra distribución no equivale a corrección.

Estos informes pertenecen a los ImageID originales. **No son scans del bootstrap
APT protegido ni de la candidata AUTH-01.** La nueva candidata conserva identidad
y resultados propios en [AUTH-01.md](AUTH-01.md). Las huellas SAST históricas
tampoco se hacen pasar por las de archivos modificados; se conserva la necesidad
de nueva medición del código cambiado. No se reabre la auditoría general de CVEs.

AUTH-01 añade dos mediciones SAST reales en `candidate_sast_attempts` del JSON:
33 LOW en el primer intento y 32 LOW en el segundo (13 B404 y 19 B603).
Se guardan ambos informes, ImageID, hashes de fuentes y evidencia. B607 desaparece
al usar rutas absolutas verificadas para Git/Docker; no se aplicaron supresiones.
El segundo SAST devuelve salida 1: **no está aprobado**, y los 32 findings siguen
registrados, no aceptados. Los 28 históricos se conservan con sus fuentes propias.

Todos los riesgos pendientes comienzan como **registrado_no_aceptado**.
Responsable individual: por designar por el propietario. Próxima revisión:
2026-11-24, o antes de proponer publicación, lo que ocurra primero. No hay
aceptaciones ni aprobadores: su expiración es `null` porque ninguna fue concedida,
no porque sean ilimitadas. Una aceptación futura necesitaría alcance, responsable,
aprobador, evidencia, fecha de expiración y revisión ante cambios de código/entorno.

La mitigación del desarrollo es aislamiento local, datos sintéticos, recursos
propios, sin salida externa durante integración y sin exposición pública. No
remedia vulnerabilidades del decoder ni sustituye el worker multimedia pendiente.
Un administrador de usuarios tampoco recibe acceso global a proyectos privados.
Argon2id, CSRF y PostgreSQL no aceptan los 28 findings SAST ni los críticos OS.

El importador `scripts/build_risk_register.py` lee únicamente los informes
enumerados, comprueba identidad/conteos y exige salida nueva. No ejecuta scanners,
lee datos operativos, modifica políticas o atribuye evidencia a otra imagen.

## Observación real CI-AUTH-01 en GitHub, 2026-11-11

[Run 42947739289](https://github.com/AldemaroCruz/ClipForge/actions/runs/42947739289),
commit `7fe3a486911c281c58fb7de3df72ad87f2c696e9`. Se reutilizó la descarga
`clipforge-ci-42947739289-1`; no se repitieron builds, tests o scanners.
Los informes anteriores y sus severidades se conservan. Las 4.717 observaciones
previas permanecen intactas y se añaden **754 observaciones: 715 SCA y 39 SAST**.
El JSON contiene 5.471 registros en `records`, además de los intentos SAST
históricos AUTH-01 que ya tenían su sección propia. Los flags `current_attempt`
de esos intentos conservan su alcance histórico, no designan el último run.

| Imagen analizada en este run | HIGH | CRITICAL | IDs únicos | Alcance de los hallazgos |
| --- | ---: | ---: | ---: | --- |
| CI | 281 | 1 | 66 | Paquetes OS; Python/Node sin findings dentro de este filtro H/C |
| Browser | 283 | 1 | 68 | Paquetes OS, incluidos dos findings adicionales de CUPS |
| PostgreSQL | 147 | 2 | 62 | 123 filas OS y 26 Go/stdlib dentro de gosu |

La unión contiene **97 identificadores distintos**; no se suman las tres columnas
como CVEs únicos. El motor PostgreSQL 18.6, paquete `18.6-1.pgdg13+2`, sí está
inventariado y en SBOM, pero ningún finding de este reporte se le atribuye.
Eso no demuestra ausencia de vulnerabilidades del motor.

CRITICAL observados, sin remediación ni aceptación:

- Las tres imágenes: `libxml2=2.12.7+dfsg+really2.9.14-2.1+deb13u3`,
  **CVE-2026-6653**, SeveritySource `nvd`, DataSource Debian, estado `affected`,
  sin FixedVersion en el JSON.
- PostgreSQL: **CVE-2025-68121** en Go `stdlib v1.24.6`, embebida en
  `/usr/local/bin/gosu` 1.19; no es la versión del servidor SQL. SeveritySource
  `nvd`, DataSource Go. `Status=fixed` y las versiones catalogadas no prueban que
  el binario instalado esté corregido.

Bandit 1.9.4 registró **39 hallazgos de cuatro reglas**: 15 B404, 20 B603,
3 B108 y 1 B105; 36 LOW y 3 MEDIUM, cero errores. No se clasificaron como falsos
positivos ni se aceptaron por ser herramientas de CI. Las severidades y la
ausencia original de SeveritySource en algunas filas SCA se conservan literalmente.

Las identidades, hashes de reportes, DB y fuentes exactas están en
`github_run_observations` y `sources` del JSON. La DB compartida registrada por
el run es Trivy 0.76.2/schema2, SHA256
`cf7fa3086682e8f77298ca8178419a530f97d7c4bd3ac203a64f2977f82e94a6`.
Los JSON de imagen no contienen por separado ese hash de DB.

El rechazo final es exclusivamente `security_finding` en bandit, trivy,
browser-trivy y postgres_trivy. Las pruebas funcionales y limpieza pasan;
**registrado no significa aceptado**. Pro/ESM sigue aplazado, presupuesto de
servicios nuevos cero y release/despliegue bloqueados. Estos scans no describen
la instalación operativa. Detalle: [cierre CI-AUTH-01](CI-AUTH-01.md).
