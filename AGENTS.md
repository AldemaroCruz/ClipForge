# ClipForge: instrucciones de desarrollo

La carpeta de trabajo autorizada es `C:\Users\itres\Desktop\clipforge-mvp`.
También contiene una instalación v0.4.2 operativa: autorizar cambios de código
no autoriza actualizar, reconstruir o reemplazar su servicio.
La copia `C:\Users\itres\source\repos\clipforge` se conserva; no escribir,
sincronizar, fusionar ni borrar esa copia como parte de CI-01, SEC-01, SEC-02 o SEC-03.

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
intento usa directorios propios. GitHub Actions sigue pendiente hasta ejecutarlo.
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
