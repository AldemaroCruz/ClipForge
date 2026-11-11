# ClipForge: instrucciones de desarrollo

## Publicación puntual AUTH-02 autorizada

El propietario revisó AUTH-02-review-final.patch SHA256
`e1ca7a3e544483002938576d1c6be18cf36c20cfea87bd830ea4ef021b156b8c` y autoriza
commit específico y push normal solo a `ci/bootstrap-sec03` en
`AldemaroCruz/ClipForge`, tras verificar selección y escanear los blobs exactos
del índice con la configuración versionada de Gitleaks. No reaplicar el patch.
La única clasificación nueva autorizada es el checksum público en la asignación
exacta de FROZEN_AUTH01_DDL_SHA256 de tests/test_auth_recovery.py. Usar defaults
nativos completos y AND regla/ruta/línea literal; cambios requieren revisión.
Mantener originales, probar precisión con scanner real y observar Actions del SHA
nuevo. Sin excepciones Bandit/Trivy, force-push, merge, tags, release, despliegue,
servicios pagos, Pro/ESM, cambios operativos ni datos del propietario.

## AUTH-02 autorizado, sin promoción

AUTH-02 autoriza recuperación de cuentas normales activas por administrador con
sesión, CSRF y reautenticación limitada; códigos de alta entropía, hash solamente,
15 minutos, un uso y revocación transaccional de sesiones. No recuperar admins,
reactivar cuentas, cambiar roles/propiedad, impersonar o enviar correo externo.
Auditoría persistente sin secretos y consistente con las acciones; revisión nueva
sin editar DDL histórico. UI administrativa paginada y solo lectura.
Pruebas en nueva candidata/PostgreSQL propios con datos sintéticos; conservar la
candidata del propietario y la instalación operativa. Nuevo recorrido real de
browser obligatorio en CI, además de los seis previos y AUTH-01; mantener gates.
Puede crearse solo el commit documental separado de CI-AUTH-01 con los tres
archivos revisados y escaneo de blobs exactos del índice. Sin commit de código
AUTH-02 ni push hasta revisar la entrega. SEC-05/Pro/ESM siguen aplazados,
presupuesto cero y release/despliegue bloqueados. Esta autorización reemplaza la
exclusión histórica de recuperación únicamente para este alcance.

## Integración CI-AUTH-01 autorizada

El propietario revisó AUTH-01 (patch SHA-256
`ad0bdbc752e60e2a17bd16646ddeb85057619e79ab56ab07c8336e5726d42ec7`, 61 archivos)
y autoriza commits específicos de AUTH y su integración, selección explícita,
escaneo de los blobs exactos del índice y push normal únicamente a
`ci/bootstrap-sec03` en `AldemaroCruz/ClipForge`. Conservar cualquier diferencia
posterior hasta revisarla. Sin force-push, merge, tags, release o despliegue.

CI usa PostgreSQL efímero exclusivo, imagen fijada, migraciones reales, rol de
aplicación propio y red Docker interna sin salida externa. No reutiliza la
candidata del propietario, sus usuarios, secretos, volúmenes o estado externo.
La limpieza se limita a los recursos identificados de la ejecución, también
ante fallo/cancelación. Se conserva UID/GID explícito de CI-FIX-01.

Son obligatorios suite completa con discovery real, checks nativos, los seis
escenarios browser previos y AUTH real adicional. El validador exige resultados
AUTH, aislamiento/limpieza e inventario/SBOM/SCA propios de PostgreSQL; no inventa
targets Python/Node para esa imagen ni omite otros componentes presentes.
No publicar secretos, dumps, estado privado del lanzador o inspect con variables.

No reabrir SEC-05, cambiar distribución, implementar recuperación de cuentas ni
contratar servicios/Pro/ESM/cloud. La candidata de desarrollo y la instalación
operativa se preservan. No declarar Actions validado antes de observar el run
del SHA nuevo. Un fallo nuevo exige conservar evidencia y presentar causa y
corrección mínima; no encadenar reintentos. Estas autorizaciones reemplazan solo
las restricciones de commit/push de AUTH-01 para el alcance revisado.

## Prioridad AUTH-01 (decisión del propietario, 2026-11-10)

La prioridad actual es desarrollo funcional local. Presupuesto de nuevos
servicios: **cero**. Ubuntu Pro/ESM y la comparación de distribuciones quedan
aplazados; no se reabre SEC-05 como requisito para desarrollar funciones.
Se conservan sus archivos y expedientes fuera del patch de AUTH-01.

AUTH-01 autoriza autenticación y usuarios sobre FastAPI, PostgreSQL local,
Argon2id, sesiones revocables, CSRF, aislamiento por espacio privado, interfaz,
migraciones y dependencias/locks necesarios. No autoriza actualizar todo el
stack. El coordinador integra; hasta tres especialistas backend, QA e
infraestructura pueden editar archivos asignados sin solapamientos ni subagentes.

Las integraciones aplicación/PostgreSQL pueden usar una red Docker **interna
sin salida externa**, comprobada y descrita como tal. No se las denomina
`--network none`. Preparación/descargas separadas; recursos, volúmenes y claves
de desarrollo propios. `compose.dev.yaml` es independiente; acceso host solo
loopback, puerto disponible distinto de 8080, PostgreSQL sin puerto publicado.
El HTTP local exige perfil explícito; los demás entornos requieren cookies Secure.

Desarrollo y pruebas locales están permitidos con riesgos documentados,
**registrados, no aceptados**. Los findings reales y el bloqueo histórico de
release siguen visibles: no suprimir scanners, bajar severidades, aceptar
críticos/SAST o atribuir scans históricos a imágenes nuevas. Publicación,
Internet, release, despliegue, GCP/Terraform, servicios pagos, Pro/ESM y
commit/push siguen sin autorización en AUTH-01. No se modifica la instalación
operativa ni se migran datos reales; futuras migraciones se prueban con fixtures.
OAuth social, correo externo, MFA y worker multimedia quedan fuera del incremento.

Las restricciones históricas siguientes permanecen salvo las ampliaciones
explícitas de AUTH-01 anteriores; autorizaciones Git previas no se reutilizan.

La carpeta de trabajo autorizada es `C:\Users\itres\Desktop\clipforge-mvp`.
También contiene una instalación v0.4.2 operativa: autorizar cambios de código
no autoriza actualizar, reconstruir o reemplazar su servicio.
La copia `C:\Users\itres\source\repos\clipforge` se conserva; no escribir,
sincronizar, fusionar ni borrar esa copia como parte de CI-01 o SEC-01 a SEC-04.

- La sesión principal coordina; puede delegar como máximo a tres especialistas
  de QA, seguridad e infraestructura. Los especialistas no crean coordinadores
  ni subagentes. Comunicar la ruta y asignar archivos distintos antes de editar.
- No leer ni copiar `data/`, `cache/`, `backups/`, `release/`, `evidence/`,
  `test-evidence/`, `restore-check-*/`, `.env`, `.env.ai`, credenciales, videos
  ni estados Terraform. No expandir configuración del Compose operativo.
- Antes de cambios que pudieran afectar el servicio, comprobar solo sus
  montajes y comando de arranque, sin inspeccionar variables de entorno.
- Para CI usar `scripts/prepare_ci_context.py` y verificar su manifiesto antes
  del build. No enviar la raíz de esta instalación como contexto Docker.
  `Dockerfile.ci.dockerignore` es independiente del ignore operativo.
- El scanner de secretos recibe un snapshot de `prepare_ci_scan.py`, no la
  raíz. Validar todos los nombres versionados antes de abrir archivos; rechazar
  incluso privados forzados en Git. Solo se permite `.env.ai.example` como
  ejemplo. Sin Git local, usar una lista explícita y declararlo en la evidencia.
- No usar la imagen, locks, Compose, contenedores o volúmenes operativos para
  probar. Crear recursos propios con nombre exclusivo; los tests van sin red,
  claves ni montajes de la raíz del proyecto. Preparar descargas por separado.
- No debilitar pruebas, scanners, hashes o precisión temporal. Los resultados
  deben distinguir checks reales, fixtures/simulaciones y pruebas pendientes.
- No consultas pagadas a IA, commits, push, despliegues, cambios IAM,
  `terraform apply` o limpieza global de Docker sin autorización posterior.
- SEC-01 autoriza actualizar pins solo para hallazgos verificados o su
  compatibilidad, después de documentar el diagnóstico y las regresiones.
  Mantener los demás componentes. No forzar dependencias incompatibles,
  extrapolar fixes entre distribuciones, ocultar herramientas ni suprimir
  hallazgos. Sin fix disponible, conservar el bloqueo. Una resolución nueva
  de CI no es una captura ni una validación de la instalación operativa.
- No declarar GitHub Actions validado antes de ejecutarlo en GitHub.
- SEC-02 autoriza reemplazar únicamente los siete assert del checker de
  branding por validaciones equivalentes. La revisión de subprocess y OS no
  autoriza modificar esas llamadas, excluir hallazgos o cambiar la política.
  El validador versionado exige alcance y paquetes completos, además de IDs;
  nunca completar métricas faltantes de informes antiguos. Separar fixtures
  del contrato de los informes reales y conservar cada intento.

Alcance y comandos: [docs/CI.md](docs/CI.md). Diagnóstico y estado SEC-01:
[docs/SEC-01.md](docs/SEC-01.md). Conservar los informes anteriores; un nuevo
intento usa directorios propios. Actions se ejecutó: CI-FIX-01, commit
`2c5ea13e4c5935bad84a0ce7ad6c453fe221e52c`, run `42866539507`.
Permisos comprobados en Ubuntu; CI/release/despliegue siguen bloqueados por seguridad.
Resultados y pendientes SEC-02: [docs/SEC-02.md](docs/SEC-02.md).

SEC-02 terminó su alcance técnico local; CI/release/despliegue siguen sin aprobar.
SEC-03 solo autoriza retirar el import sin uso de `subprocess` en `app/main.py`
y limitar/validar la consulta de versión FFmpeg en `scripts/capture_runtime.py`,
con tests aislados. No ejecutar esa captura contra el servicio o su caché.
La propuesta SAST no aplica aceptaciones ni modifica reglas/umbrales/validador.
Git se prepara mediante selección explícita y snapshot escaneado; `git init`,
`add`, `commit` y `push` requieren autorización específica de cada paso.
No inventar identidad de autor. Estado: [docs/SEC-03.md](docs/SEC-03.md).

GIT-01 autoriza inicializar esta carpeta, usar la selección explícita revisada,
crear el commit y enviar únicamente `ci/bootstrap-sec03` al repositorio
`https://github.com/AldemaroCruz/ClipForge.git`, después de verificar identidad,
autenticación, visibilidad, remoto vacío y escaneo del contenido exacto del
índice. No usar Stage All, `git add .`, force-push o integrar contenido remoto
inesperado. No crear un PR sin una rama base existente. Esta autorización no
aprueba CI/release/despliegue ni excepciones de seguridad o cambios operativos.

CI-FIX-01 autoriza el contrato de permisos del workflow, con un commit y push
normal a `ci/bootstrap-sec03` y una ejecución nueva. Los escritores de scratch
usan UID/GID explícitos del runner; los permisos se prueban sin capacidades
adicionales, chmod 777, cambios de aplicación o excepciones de scanners.
No atribuir fallos de preparación a CVE. Si aparece otro error independiente,
conservar evidencia y proponer el siguiente paso sin encadenar reintentos.

SEC-04 autoriza el selector confiable de FFmpeg/ffprobe para candidatas Linux y
comparación causal de detecciones con imágenes/DB identificadas. No buscar
alternativas en PATH, introducir rutas Linux en ejecución nativa Windows ni
suprimir B404/B603. La compatibilidad declarada sigue siendo Docker Desktop
con contenedores Linux. Conservar permisos de CI-FIX-01 e informes históricos.
No actualizar pins sin fix verificable de la misma distribución. No crear
commit/push/merge/release en este incremento antes de revisar la entrega.
Estado y decisiones: [docs/SEC-04.md](docs/SEC-04.md).
