# DB-01: candidata completa de inicialización y aceptación

**Preparada para revisión; activación INT bloqueada.** El operador guest completo,
el lanzador y el cliente de aceptación están implementados como candidatas. No
se ejecutó inicialización, formato, SQL en INT, publicación de secretos, creación
de Jobs, cambios IAM o despliegue. La propuesta versionada conserva las banderas
de activación en false; no es una autorización implícita por tener código completo.

## Evidencia y bloqueos actuales

GUEST-01 run 44413106524 observó Debian 13 trixie, PostgreSQL/cliente17.12-0+deb13u1,
kernel6.12.117+deb13-cloud-amd64, ambas unidades masked/inactive/dead, cero clusters,
procesos PostgreSQL y listeners5432. El inventario no observó by-id/SERIAL.

La observación real **run 44424226652, intento1, SUCCESS**, fuente
6e0c00020391aff119b420f4347df553311039a1 y payload
bbdf67688a9d5f0e71f2e3009b9a6d0ed13f75f42892baab60b5f18efeee6d6c,
tiene resultado observation_complete y observación guest fechada
el 19 de noviembre de 2026 a las 01:03:53 UTC. Sus dos JSON se verificaron por hash:

- inventory.json: 748af07defac48b57236a204701988d849c51372390a36e5cf7c4ecdcc35f5b1.
- disk-proof.json: b13f463421971298a57e47e4e552d0f0bdad40c8beb23b61edfe80754ef4efab.

La cadena control-plane/guest queda observada: disco GCP 6427691858848206684,
pd-standard21474836480bytes, VM 1670495097211408131, attachment
clipforge-pg-data/SCSI/index1/READ_WRITE/boot=false/autoDelete=false;
/dev/disk/by-id/google-clipforge-pg-data resuelve a /dev/sdb, major:minor 8:16.
lsblk SERIAL y udev ID_SERIAL_SHORT coinciden exactamente en clipforge-pg-data.
**El serial sysfs sigue null antes y después**; no se rellena ni se le atribuye
la observación de las otras dos fuentes.

Antes/después coinciden: boot_id5a3bfee3-9db5-4061-9bc2-8eb622d139bd,41943040
sectores, sin holders; raíz 8:1 sobre sda/sda1, fuera del sysfs de sdb. lsblk no
reporta filesystem, particiones ni montajes y wipefs --no-act devuelve firmas
vacías. Las cuatro consultas nativas adicionales terminaron0, sin stderr;
las guardas base siguieron pasando. Esto demuestra esa correlación y ausencia
de firmas reconocidas en ese momento; no sectores vacíos ni autorización de formato.

El proof recomputado con la fuente actual coincide con disk-proof.json y su
shape/valores son compatibles con el operador dd478 congelado. La validación
pura en envoltura sintética pasó en la hora observada y rechazó antigüedad301s;
no simula aprobación operativa, TLS real ni ejecución del operador. El hash de
los bytes del bundle público reconstruido coincide con el payload real. El
check POSIX de permisos de archivos no se atribuye a Windows. Una inicialización
futura debe volver a leer el guest antes del límite y cumplir el TTL 300 s.

La nueva observación también conserva368 filas reales de paquetes con nombres
y versiones fuente. No se completaron retroactivamente los informes SCA anteriores;
un SCA nuevo sobre esos campos requiere su propio resultado y procedencia.

El SCA anterior se conserva: 1 CRITICAL, 25 HIGH y 172 filas, sin campos fuente
observados. El nuevo SBOM usa los siete campos reales de los 368 paquetes y el
scan con la misma herramienta/DB produce **7 CRITICAL, 208 HIGH y 1033 filas**
(372 identificadores únicos). Los binarios coinciden exactamente entre capturas:
el aumento corresponde a la cobertura corregida de fuentes, sin actualizar la VM.
El análisis incluye 20 grupos fuente pendientes de revisión individual; no informa
versión corregida para sus 215 filas CRITICAL/HIGH. La matriz completa está en
la evidencia privada. No es un scan del filesystem ni una aceptación de seguridad.
Los hashes actuales y los anteriores, separados, están en la propuesta JSON.
CVE-2026-6653/libxml2 continúa bloqueante; el diff adaptado sólo tiene una prueba
de aplicabilidad, sin paquete, ABI ni resolución de la CVE demostrados.

CI aplicación C1 run 44424151788 terminó failure. Los controles de integridad de
C1 run 44424151652 pasaron, con seguridad bloqueada. Son resultados distintos.
La candidata final aún requiere su commit exacto, scanners, revisión y evidencia
propia; ni GUEST ni compatibilidad PG 17 sustituyen el gate de aplicación.

## Entradas protegidas pendientes

La consulta de nombres del environment `int` devolvió HTTP 200 el 18 de noviembre
 a las 18:17:47 de Guatemala (19 de noviembre, 00:17:47 UTC). No estaban presentes
`INT_APP_PASSWORD`, `INT_MIGRATOR_PASSWORD`, `INT_POSTGRES_CA`,
`INT_PG_SERVER_CERT` ni `INT_PG_SERVER_KEY`. No se leyeron valores.
Se requiere una provisión protegida aprobada por separado, con passwords distintos,
CA de confianza, certificado serverAuth/SAN IP `10.80.1.2` y pareja de claves.
El lanzador y el guest exigen al menos siete días de vigencia restante para
certificado y CA. Ninguna clave privada de CA entra en este flujo; la clave del
servidor sólo se transportará por stdin cifrado hacia su archivo restringido.

Los gates nuevos rechazan la operación si falta autorización expresa de SQL,
formato, VM o ejecución. También exigen el argv exacto sin `-F`, el ID/confirmación
del disco, una decisión puntual de hasta 60 minutos y sus hashes. La propuesta
actual mantiene todas las autorizaciones en `false`. Las aceptaciones anteriores
de fundación no cubren esta activación ni sus nuevos hallazgos.

## Fronteras del flujo preparado

1. Bootstrap guest de una única VM/disco mediante Deploy WIF, OS Login email,
   clave cliente propia TTL 900 y host Ed25519 ya verificado. Nunca repetir el
   publicador de host, stop/start de VM o ampliación IAM.
2. Publicación **separada y autorizada** de sólo tres versiones: password app,
   password migrator y CA pública. Usar exactamente los mismos valores protegidos
   que la DB y referencias numéricas, nunca latest. No publicar server.key,
   CA private key ni bootstrap-admin como parte de esa fase.
3. Dos Jobs Direct VPC propuestos —migración y aceptación app— con identidades
   separadas, recursos/plan aún sujetos a revisión y **OCI publicado pendiente**.
   No convertir la VM o el runner hospedado en cliente del CIDR Run.
4. Migrator aplica AUTH/cloud y comprueba segunda ejecución current; app comprueba
   TLS, rol, DML y denegaciones DDL desde10.80.0.0/26. Un fallo parcial conserva
   revisiones comprometidas y no autoriza repetición automática.
5. Alta inicial de administrador, backup/restore y aplicación quedan diferidos.
   Habilitar PostgreSQL no demuestra protección de datos o runtime aprobado.

## Contrato del operador y preflight antes del límite irreversible

scripts/int_bootstrap_vm.py recibe únicamente JSON por stdin, máximo64KiB,
schema clipforge-db01-bootstrap-input-1. Campos exactos: schema, operation_id,
approved_commit, proposal_sha256, operator_sha256, confirmation, disk_proof y
secrets. El loader comprueba la fuente pública y fija DB01_OPERATOR_SHA256.
No acepta el payload legacy ni argumentos CLI; secretos nunca en argv/metadata/log.

El proof de int_guest_db_observe.disk_proof usa disk_type como URL GCP exacta y
campos interface/index/mode; liga recibo y fuente del observador, VM, último
arranque, boot_id, disco, by-id, tamaño y metadatos guest realmente observados.
El launcher liga la misma fuente/commit/propuesta/host/baseline y exige decisión
cerrada, ventana vigente, CI exacto y aprobación manual de int. Los flags
SQL_on_INT_authorized y format_operation.authorized también deben autorizar
explícitamente la operación; ninguna bandera false se ignora para activarla.

El guest exige Linux root, metadata IMDS de VM/proyecto/zona y boot_id correctos.
Comprueba comandos absolutos root-owned sin búsqueda PATH, paquetes17.12 exactos,
cuenta OS postgres sin uid/gid0, unidades masked/inactive/dead, cero clusters,
procesos y sockets5432, directorios iniciales seguros y localeC.UTF-8/C.utf8
existente. No instala herramientas, actualiza APT ni adopta instalaciones.

Antes del formato y mediante lecturas nuevas: by-id root-owned resuelto a bloque,
major:minor exacto, tamaño21474836480, sin holders/particiones/montajes/firmas y
fuera del dispositivo raíz. Compara seriales presentes sin quitar prefijos:
sysfs opcional sólo si FileNotFound, lsblk SERIAL y udev ID_SERIAL_SHORT; al menos
uno real y todos coherentes con el proof. EACCES, consulta desconocida o discordancia
bloquean. Proof de máximo300s, revalidado inmediatamente antes del límite.
Google explica los [enlaces estables por deviceName](https://docs.cloud.google.com/compute/docs/disks/disk-symlinks);
sdX no se usa como identidad permanente.

TLS se prevalidará en el runner y se verifica otra vez en el guest **antes del
journal irreversible**: cadena, serverAuth/purpose, SAN IP10.80.1.2, pareja de
clave/certificado y al menos siete días restantes en CA y leaf. Passwords app y
migrator distintos,32–4096 ASCII gráficos. No CA key; certificados no admiten
claves privadas embebidas. No certificado/verifier/password se publica en recibos.

fstab se lee y valida antes del formato. La preimagen privada se guarda con0600;
si cambia antes o después del formato se preservan los bytes ajenos y se para.
El reemplazo es atómico y exige preimagen idéntica. No hay exclusión atómica
contra otro root entre comparar y rename: la ventana debe excluir trabajo paralelo.

## Secuencia guest preparada, todavía no autorizada

Cada intención y resultado se guarda con fsync en journal root-owned0700,
operation.json0600. Cualquier journal previo, incluso del mismo operation_id,
bloquea replay y queda intacto. No se elimina ni reconstruye para continuar.

El único comando de formato preparado es exactamente, **sin -F**:

    /usr/sbin/mkfs.ext4 -L clipforge-int-pg /dev/disk/by-id/google-clipforge-pg-data

Requiere confirmación INITIALIZE_NEW_DISK_6427691858848206684, proof completo,
fuentes revisadas y activación explícita. Tener el argv preparado no autoriza
su ejecución; la observación real anterior debe revalidarse fresca dentro del flujo protegido.

Después: registrar UUID, añadir una sola línea fstab por UUID con
ext4/defaults,nodev,nosuid,noexec, montar en /var/lib/clipforge-postgres/data y
verificar UUID/source/major:minor/ext4/rw y las tres opciones restrictivas. Si el
montaje falta, no crear pgdata sobre la raíz.

Antes de cluster_create se registra el cambio exclusivo del padre
/var/lib/clipforge-postgres desde root:root0700 a root:grupo-postgres0710:
ejecución de grupo sin listar/escribir. Procedencia0600 y journalroot0700 siguen
privados. Se verifica el estado efectivo; el mountpoint pasa a postgres0700.
Cluster17/main manual en data/pgdata, con --encoding=UTF8 --locale=C.UTF-8.

Configurar listen_addresses10.80.1.2/puerto5432, TLS mínimo1.2, archivos de
certificado/clave/CA postgres0600 y password_encryption=scram-sha-256. HBA sólo:

    local all postgres peer
    hostssl clipforge clipforge_app 10.80.0.0/26 scram-sha-256
    hostssl clipforge clipforge_migrator 10.80.0.0/26 scram-sha-256

Desenmascarar las dos unidades previstas e iniciar sólo postgresql@17-main.
Crear dos roles LOGIN/NOSUPERUSER/NOCREATEDB/NOCREATEROLE/NOREPLICATION/NOBYPASSRLS;
DBclipforge propiedad de migrator. Revocar privilegios PUBLIC de DB y CREATE de
schema public; app sólo CONNECT/USAGE y defaults DML de tablas/USAGE+SELECT de
secuencias creadas por migrator. CREATE DATABASE es un límite de commit separado;
no se presenta toda la inicialización como transacción única.

Postchecks nativos: montaje, archivos idénticos, configuración efectiva sin
errores, versión170012, UTF8 y datcollate/datctype de pg_database (no GUCs SHOW),
roles/owner/ACL/defaults, cluster único online y handshake TLS local verificado.
Sólo después start.conf=auto y servicio habilitado. PostgreSQL documenta
[permisos TLS](https://www.postgresql.org/docs/17/ssl-tcp.html) y
[verify-full/CA/identidad](https://www.postgresql.org/docs/17/libpq-ssl.html).

boot_persistence_configured sólo demuestra configuración, no reboot ni éxito
del startup de Google. El startup a93 permanece intacto: al detectar el futuro
postgresql.conf termina para revisión manual antes de APT/masks. No ocultar ese
resultado ni repetir el instalador. Reboot/cambio de startup están fuera de este
flujo preparado.

## Recibos, tiempos y errores

El recibo clipforge-db01-bootstrap-receipt-1 liga operación/commit/propuesta/fuente,
proof y fuente/recibo del observador, fase, journalSHA, UUID, hashes de config/fstab,
permisos antes/después, checks y45 resultados nativos en orden exacto.

| Exit | Estado | Lectura |
| --- | --- | --- |
| 0 | configured_guest_verified_external_acceptance_pending | Checks guest completos; aceptación externa pendiente |
| 2 | blocked | No se creó el journal de inicialización |
| 3 | partial_preserved | Operación parcial, previa o indeterminada; preservar y no repetir |

Los flags runtime_authorized, external_client_acceptance, migrations_applied,
administrator_bootstrapped, restore_verified y security_accepted permanecen false.
Un handshake local no demuestra login de app/migrator desde Run: HBA no se amplía
para fingir esa prueba desde la propia VM.

Guest 540 s, SSH 600 s con 60 s de protocolo y clave 900 s con margen de limpieza. Nativo
≤120s, stdout≤64KiB/stderr≤8KiB durante lectura. Timeout/cap/nonzero se conservan
con exit real; no se green-ea un fallo posterior. Sólo frases literales permitidas
y conteo de líneas desconocidas, sin afirmar conservar texto no clasificado.
Si falla guardar el journal se conserva el error primario y se añade
journal_error_code=journal_update_unconfirmed. Syscall ininterrumpible o transporte
perdido siguen indeterminados: no ampliar TTL ni repetir operación.

No existe rollback a disco virgen: nunca reformat, wipefs de escritura,
pg_dropcluster, borrado/adopción de pgdata o inverse migration. Contención manual
futura sólo del cluster exacto y cambios propios comprobados; conservar disco,
UUID, journal y configuración parcial. Restaurar fstab sólo si sigue idéntico al
sucesor propio. Secret-version desconocida no se repite, rota o destruye.
Limpieza de transporte sólo de procesos/clave OS Login/temporales propios.

## QA y decisiones restantes

Las27 pruebas propias del guest usan archivos desechables y mocks de procesos,
metadatos/sysfs/SQL; no son ejecución de VM, TLS nativo o aceptación cloud.
La compatibilidad PG 17 y el cliente nativo tienen evidencia propia separada.
Mantener public schema, roles separados, UTF8/C.UTF-8, TLS/SCRAM y las negativas;
fixtures con schemas de prueba nunca justifican CREATE para app.

Para activar faltan: relectura fresca del observador dentro del flujo, propuesta
final con fuentes/format/SQL coherentes, clasificación de seguridad, CI exacto,
decisión operativa y aprobación int. Para aceptación externa también faltan
imagen/digest publicado, tres versiones numéricas autorizadas y plan/creación
independiente de los dos Jobs. Admin, backup/restore y runtime siguen diferidos.
