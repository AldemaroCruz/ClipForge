# CI-FIX-01: permisos de scratch entre runner y contenedores

El primer run [42859254764](https://github.com/AldemaroCruz/ClipForge/actions/runs/42859254764)
del commit `f0cdfd29107229761aa2663bae9fee36ffd89e33` falló descargando la DB
Trivy: `mkdir /cache/db: permission denied`. El build, los tests y los scans
de aplicación no se ejecutaron. Se conserva el workflow original y sus logs
en `.ci-local/ci-fix01-b6e01459/`. Es un fallo de infraestructura, no un CVE.

## Diagnóstico medido y límites

No se imprimieron variables de entorno o credenciales. Se consultó únicamente
`Config.User` de las imágenes fijadas y se midieron UID/GID efectivos, capacidades,
NNP, propietarios/modos y opciones de los montajes en contenedores propios.

| Imagen | Config.User | UID:GID efectivo predeterminado |
|---|---|---|
| Trivy 0.76.2 | campo no serializado | 0:0 |
| Gitleaks 8.30.1 | campo no serializado | 0:0 |
| CI y browser conservadas | campo no serializado | 0:0 |
| Actionlint 1.7.12 | guest | 405:100 |

Con `--cap-drop ALL`, CapEff/CapPrm/CapBnd son cero y NNP=1. En tmpfs POSIX
propio, directorios de UID1001/GID1001 y modo0755 rechazaron escrituras de
esas identidades predeterminadas; UID1001:GID1001 pudo crear/leer/eliminar
archivos0600. Un oracle independiente confirmó errno30/EROFS en entradas RO.
No hubo chmod/chown o capacidades adicionales para preparar ese recurso.

Esto confirma el mecanismo: root sin capacidades no puede ignorar permisos
de un directorio ajeno. El run original no registró UID/GID y stat del runner;
no se inventan sus números ni su modo histórico. La ejecución corregida debe
medir en Ubuntu los valores reales, compararlos con los del contenedor y
conservarlos en los reportes. Docker Desktop y los lectores Linux simulados
no sustituyen esa evidencia.

## Corrección mínima

- El runner obtiene UID/GID con `id`, valida valores numéricos/no-root y crea
  únicamente su scratch nuevo con umask077 y directorios0700.
- Trivy escribe `/cache`, `/reports` y `/scan-tmp` con `--user UID:GID` del runner.
  Su consulta de versión también usa esa identidad para leer cache0700.
- Gitleaks escribe `/reports`; tests, inventarios, Bandit y browser escriben
  `/ci-results` con esa misma identidad explícita.
- `/scan-tmp` pasa del volumen creado por Docker a un bind de un directorio
  exclusivo bajo RUNNER_TEMP, creado por el runner. No se presume propiedad
  del volumen ni se necesitan chown, capacidades extra o chmod777.
- Actionlint y comandos de versión que solo leen/usan stdin y entregan stdout
  al host conservan su identidad predeterminada. APT dentro del build no cambia.
- Se mantienen raíz readonly, cap-dropALL, no-new-privileges, entradas RO,
  scans/tests sin red, descargas en preparación separada, digests y salidas.
  El cleanup comprueba ruta exacta, realpath, propietario y ausencia de symlink
  antes de eliminar solo el scanner-tmp propio.

## Sonda permanente y comprobaciones locales

`scripts/check_ci_permissions.sh` es un orquestador Bash del host; se ejecuta
desde su ruta versionada explícita. No se amplía el contexto Docker de aplicación
para incluirlo. El snapshot de secretos sí admite y escanea este `.sh`.

Para cada perfil comprueba identidad y propietario0700, capacidades cero/NNP1,
raíz/entrada RO, create+unlink en cada destino RW y una entrega0600 que el runner
lee y elimina. La fixture de entrada pertenece al mismo UID/GID y es0600; se
exige EROFS y hash intacto, evitando confundir RO con EACCES por otro propietario.
El log conserva IDs de imagen, Config.User/default UID, stat y mountflags; no env.

Los perfiles son Trivy(`/cache`, `/reports`, `/scan-tmp`), Gitleaks(`/reports`),
CI(`/ci-results`) y browser(`/ci-results`). El browser mantiene init/shm/XDG.
El workflow exige Bash syntax/ShellCheck y las sondas antes de utilizar cada
imagen escritora. Una sonda fallida bloquea; no hay fallback de permisos.

Localmente, los tests nuevos son de permisos; no requieren reconstruir la app.
Se ejecutaron además la suite y los seis escenarios browser con UID1001:GID1001,
en las imágenes de prueba conservadas, sin red, claves o datos operativos.
Los binds Windows no acreditan ownership Ubuntu; se identifican por separado
en los artefactos. No se presentan como tests ejecutados en GitHub.

## Publicación y resultado de Actions

Este incremento autoriza un commit específico y push normal a `ci/bootstrap-sec03`,
después de revisar el diff y escanear los blobs exactos. Debe disparar un run del
SHA nuevo, no re-run del commit anterior. La visibilidad pública ya está autorizada.
El SHA/run y sus resultados efectivos se registran en el informe final del
expediente local, sin anticiparlos en este documento preparado para el commit.

No se cambian dependencias, Dockerfiles, aplicación, umbrales, excepciones,
validador, Terraform, IAM o instalación operativa. Los hallazgos de seguridad
continúan bloqueando cuando sus scanners puedan ejecutarse. Si aparece otro
error independiente se conserva su evidencia y se propone el siguiente cambio;
no se encadenan reintentos para conseguir verde.
