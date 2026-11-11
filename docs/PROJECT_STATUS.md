# ClipForge — Estado del proyecto

**CI-AUTH-01:** AUTH-01 revisado y versionado; integración de GitHub Actions
con PostgreSQL efímero real, aceptación AUTH y cierre de recursos obligatorios.
Validación local: 681 tests, 11 checks, seis escenarios browser y siete pasos AUTH
aprobados. La autorización comprende commits específicos y push normal únicamente
a `ci/bootstrap-sec03`; conserva todos los bloqueos de seguridad y de release.
La ejecución real de Actions se identifica separadamente en el expediente:
[CI-AUTH-01.md](CI-AUTH-01.md). No se implementa recuperación de cuentas.

**Prioridad vigente (2026-11-10): AUTH-01, desarrollo funcional local con
presupuesto de nuevos servicios cero.** Pro/ESM está aplazado y SEC-05 se conserva
sin reabrir su evaluación. Se implementan cuentas, sesiones y espacios privados
sobre PostgreSQL local con recursos aislados. Los riesgos están registrados, no
aceptados; publicación, CI/release y despliegue siguen sin aprobación.
Detalle y resultados de la candidata: [AUTH-01.md](AUTH-01.md).
Los apartados siguientes conservan el historial de decisiones y ejecuciones.

GIT-01: referencia inicial autorizada en `ci/bootstrap-sec03` a partir de la
selección explícita de 127 fuentes/configuraciones/documentos. Se exige escanear
los blobs exactos del índice y verificar que el remoto esté vacío antes de enviar.
No se presupone una rama `main`, no hay PR sin base, y no se promueve el runtime.
Bandit/Trivy permanecen bloqueantes; una ejecución de Actions se documenta por
separado y no se declara validada por la existencia del workflow o del commit.

SEC-03, 10 de noviembre de 2026: correcciones mínimas de import/consulta FFmpeg,
pruebas aisladas y selección del primer commit preparada sin inicializar Git.
SEC-02 se dio por terminado técnicamente en local. **CI, release y despliegue
siguen sin aprobar; Bandit/Trivy bloquean y Actions real está pendiente.**
Estado actual: [SEC-03.md](SEC-03.md). Los resultados siguientes son históricos.

Actualización CI-01: 2026-11-09. Código operativo: **v0.4.2 con hotfixes**. No habilitado para Internet.

SEC-01 (misma fecha local): 480 tests y seis escenarios browser pasan en imágenes
aisladas; dependencias vulnerables Python y zlib remediadas con cambios mínimos.
Permanecen 226 findings/52 CVE en CI, 228/54 en navegador y 47 LOW de SAST
bloqueantes. GitHub Actions no ejecutado; servicio operativo sin promover.
Informe actual: [SEC-01.md](SEC-01.md). Los resultados CI-01 siguientes son
históricos y se conservan con sus evidencias.

SEC-02 (10 de noviembre): hardening del validador, actionlint obligatorio y
checker de branding válido con optimización. No cambia umbrales SAST, dependencias
o instalación operativa. Clasificaciones subprocess/OS y resultados integrados:
[SEC-02.md](SEC-02.md). CI y release siguen sin aprobar; Actions real pendiente.

El operador confirmó Docker Desktop funcional, restauración con hashes y fechas exactas y apertura de un proyecto recuperado. No se releyeron sus datos para CI-01. El desarrollo autorizado continúa en `C:\Users\itres\Desktop\clipforge-mvp`; la copia de `source\repos\clipforge` se conserva sin cambios. CI-01 prepara un entorno independiente desde fuentes: [CI.md](CI.md). GitHub Actions y sus protecciones remotas siguen pendientes de ejecución; no se recuperó el candidato v0.5.0-rc1 ni se incorporó Terraform.

Las secciones históricas siguientes describen la entrega del 30 de octubre; sus pendientes de Docker Desktop/restauración fueron superados por la confirmación anterior, sin inferir aceptación cloud o editorial.

CI-01 ejecutado localmente: imagen independiente Debian 13/Python 3.12, 436 regresiones y ocho checks obligatorios aprobados sin omisiones; actionlint correcto, Gitleaks sin hallazgos y SBOM generado. Seguridad bloqueada por Trivy: 234 hallazgos paquete/CVE (1 CRITICAL, 233 HIGH; 60 CVE distintos), incluidos seis HIGH de Python. Los pins directos siguen intactos. Corregir dependencias requiere un incremento explícito con regresiones, no excepciones al scanner. Evidencia: [CI.md](CI.md). Sigue pendiente la ejecución real de GitHub Actions; no hay despliegue ni Terraform implementado.

## Confirmado antes de esta entrega

El operador confirmó procesamiento local y tres propuestas IA aceptadas en v0.4.1. Eso no prueba automáticamente una nueva imagen ni todas las rutas de recuperación.

## Implementado en v0.4.2

Panel de operación, métricas aditivas por etapa y revisión humana, respaldo/restauración por CLI, lease entre API y mantenimiento, captura de versiones transitivas y hashes/revisión del modelo desde la instalación real, build heredado sin reinstalaciones, auditor de entregas y scripts de ejecución/rollback. Persistencia legacy y contrato IA conservados.

Las evidencias nuevas del paquete son de Linux/Python 3.13 y están descritas en TEST-REPORT.md. No confundir con la imagen objetivo Python 3.12 del operador. Las respuestas IA y transcripciones de tests son fixtures identificados; FFmpeg y ZIP se ejecutan realmente.

## Puertas de salida pendientes

1. Preparación/actualización real en Docker Desktop, runtime capturado y nativos comprobados.
2. Tres proyectos hablados autorizados; al menos uno completa propuesta IA → edición → aprobación → ZIP, escuchado por el operador.
3. Respaldo y restore en una carpeta limpia del equipo real, apertura del borrador/export y conservación de propuestas.
4. Identificación y conservación del mismo artefacto probado; CI privado, SBOM y scan aún pendientes de integración.

No se creó un repositorio remoto ni infraestructura GCP. No se contrató un proveedor, alteró presupuesto, subió material ni se hizo una consulta pagada. No hay cuentas multiusuario, publicación social o procesamiento distribuido.

## Próximo paso

Ejecutar Prepare-Upgrade y Start-Release con el contenedor actual preservado; comprobar `/health` y `/ops`. Registrar evidencias de aceptación y recuperación. Solo después revisar el gate y avanzar a **v0.5.0 — piloto privado GCP**, con presupuesto y proyecto propios aprobados.
