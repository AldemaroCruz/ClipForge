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
