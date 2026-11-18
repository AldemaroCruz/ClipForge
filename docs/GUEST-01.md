# GUEST-01: host key verificada e inventario protegido

La fundación cerrada permanece conservada. La intervención de host key fue
autorizada y completada; las consultas dentro del guest se ejecutan por una ruta
separada de inventario protegido. No se autorizan APT, SQL ni activación de PostgreSQL.

Destino: `clipforgebeta2`, zona `us-central1-a`, VM `clipforge-int-base-postgres`,
instance ID `1670495097211408131`, IP privada `10.80.1.2`, imagen ID
`5913446147369107523`. La metadata actual del backend conserva generación
`1795030868572779`, correspondiente al serial 7 y 42 direcciones del recibo de
cierre. No se volvió a descargar ni publicar el estado completo.

## Intervención autorizada y comprobada

La autorización específica de la propuesta `62d8a104…cbed5e` se registró a las
21:22:08 UTC del 18/11/2026, con vencimiento 22:22:08 UTC. SHA-256 de sus bytes:
`956984c5fd9aa7b0ea0c128b0f46e24a8f1e55643edc69ff5b5895db92763ee6`.
Sólo comprende los dos LOW del operador revisado para esa intervención.

Las cuatro operaciones terminaron DONE: instalación del publicador, un STOP,
un START y restauración. El mapa completo de metadata coincide con el inicial,
el startup conserva `a93bd662…af255`, y VM/discos/imagen/IP privada/OS Login
mantienen sus identidades y controles. Nuevo arranque:
`2026-11-18T13:25:45.148-08:00`. La generación del backend no cambió.

Clave de host Ed25519, obtenida del registro serial completo y único ligado al
nonce y al hash del publicador, con comprobaciones de VM antes/después:
`SHA256:xR7of9ZrB4YEThQT8mrnc7qkRY+Xt0pyhaMKPUJxA2U`.
Sólo se leyó la clave pública existente. Evidencia portátil sanitizada SHA-256:
`1963b5e52a4606a6f0b6560dcd0ab1356e36f4ec0764b4c4fc05ee99d12229a4`.
El journal, autorización, propuesta y recibo originales permanecen en evidencia
privada. La preparación revisada se conserva con su decisión pendiente original;
la autorización y el resultado son registros nuevos.

El primer run de inventario, `44406292891`, commit `0ef3625`, conserva `failure`:
WIF y las lecturas Compute de VM/discos pasaron; GET del perfil OS Login usando
el número IAM devolvió 403. No generó ni registró clave, no intentó SSH y confirmó
`no_registered_key`. Su artefacto original permanece intacto.

El SDK 582.0.0 y el [ejemplo oficial de cuentas de servicio](https://docs.cloud.google.com/compute/docs/tutorials/service-account-ssh)
usan `users/{email}`. La corrección alinea GET/import/delete con el email literal
de Deploy y deja de equiparar `LoginProfile.name` con `serviceAccount.uniqueId`:
conserva ese identificador opaco desde la primera respuesta válida, lo fija antes
de registrar la clave y lo exige también durante su retirada. El diagnóstico lee
la ruta numérica histórica y la ruta SDK con el mismo token, conservando ambos
estados HTTP; sólo email 200 y perfil válido habilitan el resto. Un 403 nunca se
convierte en perfil vacío ni justifica ampliar permisos.

La consulta administrativa acotada de auditoría devolvió HTTP 200 sin entradas;
Google documenta que [GetLoginProfile no produce Audit Logs](https://docs.cloud.google.com/compute/docs/oslogin/view-audit-logs#methods_that_dont_produce_audit_logs).
Esa ausencia no identifica el principal ni la causa del 403. El motivo histórico
queda pendiente de contraste con las lecturas del run corregido, sin nuevos grants.

La ruta `.github/workflows/int-guest-inventory.yml` usa exclusivamente Deploy
mediante WIF, environment `int`, aprobación manual, SDK 582.0.0, clave cliente
propia de 15 minutos y comprobación estricta del pin. El UID de Deploy comprobado
por IAM es `101402373862758071342`. Sus únicas escrituras cloud permitidas son
registrar y retirar esa clave pública propia de OS Login. El payload de consulta
fijo está separado del transporte y ambos tienen pruebas dirigidas; la ruta
carece de operaciones de VM, IAM, Terraform o bootstrap de base de datos.

## Lecturas previas a la intervención

A las 20:56:41–20:56:44 UTC del 18/11/2026, `hostkeys/` devolvió HTTP 404.
El serial port 1 completo (`start=0`, 226588 bytes) no contiene clave Ed25519,
huella SSH ni registro del publicador. Su contenido completo no se conservó ni
publicó. No se creó `known_hosts`. La VM sigue RUNNING en el mismo arranque
`2026-11-17T16:32:05.900-08:00`, sin IP pública, con OS Login y bloqueo de claves
SSH de proyecto. No existen hooks shutdown, startup URL, startup heredado ni
guest attributes habilitados. El startup original conserva su SHA conocido.

Lecturas de políticas con `admin@ixbalam.studio`, 20:58:32 UTC:

| Identidad | Recurso | Rol/permisos | Observación |
| --- | --- | --- | --- |
| Deploy | IAP de instancia numérica exacta | `roles/iap.tunnelResourceAccessor`; `iap.tunnelInstances.accessViaIAP` | Un binding sin condición |
| Deploy | VM | `roles/compute.osAdminLogin`; `compute.instances.osLogin`, `compute.instances.osAdminLogin` | Un binding sin condición |
| Deploy | SA `clipforge-postgres-int` | `roles/iam.serviceAccountUser`; `iam.serviceAccounts.actAs` | Un binding sin condición |
| Deploy | Proyecto | `clipforgeIntBootstrapReader`: `compute.instances.get`, `compute.disks.get`, `compute.projects.get`, `run.operations.get` | Definición y binding sin condición |
| Deploy | Proyecto | `roles/serviceusage.serviceUsageConsumer` | Binding sin condición |

Estas políticas no prueban acceso efectivo de Deploy. Compute, IAP, OS Login,
IAM, IAM Credentials y STS están habilitadas. Policy Troubleshooter está
deshabilitado y no se habilitó. No se enumeraron Denys, PAB o herencia. No hay
denegación de Deploy demostrada que justifique IAM nuevo. No aparece
`compute.instances.list` en sus bindings directos de proyecto; la revisión
estática del SDK 582 muestra GET de instancia con proyecto y zona explícitos.
La conexión futura fijará ambos y conservará cualquier error sin ampliar IAM
por una hipótesis de descubrimiento. Las ventanas anteriores siguen vencidas.

## Propuesta única para autorización

SHA-256 de `proposal.json` preparado:
`62d8a1049a78f355c0aab234389b680183f39eb651c2c08bb601190e28cbed5e`.
La inspección inicial anterior al ajuste del operador queda conservada; la
propuesta revisada es la única presentada para ejecución.

| Ejecutable o entrada | SHA-256 |
| --- | --- |
| `scripts/int_vm_hostkey.py` | `90f47688e1b53e173dfd9105d2861235b99caae59c84fce6c8205e9601ec9dd9` |
| `scripts/int_vm_hostkey_guest.py` | `a8211bbfbe29f0694f633b403fbe41e08ef6dfbc8abb9705f56e1f8e13ea10ad` |
| Publicador renderizado | `0529b95de129932593856a3a4c8c7f9a047054743ffe00fd8dbfade37122ab8f` |
| Startup original a restaurar | `a93bd662abce93b12c6389a37fccca49612ef3d1ee83eb882051cd5489daf255` |
| Test del operador | `617da83a63d55bde29de3a69032ff3a6344dcf8f5ab0c1aaf4e25ee337df5028` |

Operador previsto: sesión administrativa habitual `admin@ixbalam.studio`.
`instances.testIamPermissions`, HTTP 200 a las 21:02:59 UTC, confirmó GET,
setMetadata, stop, start y getSerialPortOutput. Esa consulta no concedió permisos.

Ventana propuesta: **60 minutos desde la autorización**, con timestamps reales
registrados antes de mutar, sin extensión automática. Se requiere JSON externo
de autorización y SHA separado; una plantilla pendiente no puede ejecutarse.

1. Revalidar identidad, discos, imagen, RUNNING, mismo último arranque, hashes,
   mapa inicial de metadata y ausencia de hooks incompatibles.
2. Un `setMetadata` con fingerprint cambia sólo `startup-script` al publicador;
   conserva las demás claves y exige operación DONE correcta.
3. Reconfirmar RUNNING y timestamp inicial. Como máximo un STOP, DONE,
   TERMINATED y mismo timestamp, seguido de como máximo un START y DONE.
4. El publicador lee sólo la `.pub` Ed25519 existente, root-owned y sin symlinks;
   no lee la privada, genera claves ni consulta tokens. Emite por serial una
   línea con nonce, identidad, hash del ejecutable y clave pública.
5. Exigir serial desde cero, registro único completo y arranque nuevo estable
   antes y después. Un buffer truncado se rechaza incluso si contiene registro.
6. Otro `setMetadata` restaura el startup original sólo si el valor actual sigue
   siendo el publicador propio exacto. Usa CAS fresco y preserva claves ajenas.
   Verifica DONE, contenido y arranque estable; no hay segundo reinicio.
   Sólo entonces crea el pin `known_hosts` estricto.

Interrupción prevista: varios minutos; cada operación y la espera de publicación
tienen límite de 180 s, HTTP de 30 s. No es una garantía de recuperación en ese
tiempo. Stop/start implica escrituras normales del SO y otros servicios de
arranque. El publisher reemplaza al instalador durante ese arranque; restaurar
metadata no incluye ejecutar manualmente el instalador ni otro ciclo. Startup
se ejecuta como root al arrancar y su salida puede leerse por
[serial port 1](https://docs.cloud.google.com/compute/docs/instances/startup-scripts/linux).

## Fallos y seguridad de esta intervención

| Situación | Recuperación prevista |
| --- | --- |
| Instalado, sin intención STOP/START, mismo RUNNING/arranque | Restore con CAS y autorización vigente; reconfirma estado/timestamp al terminar; sin pin |
| STOP enviado/indeterminado sin START registrado | Conservar publicador y detenerse; no arrancar ni restaurar automáticamente |
| START enviado con respuesta perdida | Sólo GET/poll de operación exacta, validando requestId/tipo/target; no repetir START |
| START DONE sin registro válido o serial truncado | Conservar publicador y bloquear; no segundo ciclo |
| Restore enviado con respuesta perdida | Confirmar operación y contenido actual, sin repetir POST |
| Startup ajeno, identidad/arranque cambiados o autorización vencida | Detener mutaciones y preservar journal/evidencia; recuperación adicional requiere decisión expresa |

El ajuste del operador bloquea un arranque concurrente observable tras instalar
el publicador o tras STOP. Las **32 pruebas simuladas pasan**, incluida una nueva
regresión con tres variantes. No hay exclusión atómica de otros administradores
entre GET y POST: debe evitarse trabajo paralelo durante la ventana. El canal
API y el registro dependen de la confianza en el guest; no atestan su integridad.

Bandit **1.9.4**, Python **3.12.16**, sin red sobre ambos scripts completos:

| Regla | Fuente/línea | Severidad/confianza | Decisión pendiente y controles |
| --- | --- | --- | --- |
| B404 | `int_vm_hostkey.py:20` | LOW/HIGH | Import de subprocess, utilizado para autenticación con SDK habitual |
| B603 | `int_vm_hostkey.py:324` | LOW/HIGH | gcloud con argv fijo, sin shell, cuenta fija, overrides rechazados y token sólo en memoria |

Son **dos LOW propios pendientes**, sin supresión ni aceptación heredada de
F-SAST-EXEC del apply. La autorización operativa debe cubrirlos para estos bytes
y esta única intervención. Los controles no equivalen a remediación del finding.
El inventario/SCA de la VM y la auditoría operativa continúan pendientes.

## Inventario después de verificar la host key

La conexión prevista usa Actions, WIF de Deploy, environment `int` y aprobación
manual, IAP y OS Login. Reutiliza alias por instance ID, Ed25519 y
StrictHostKeyChecking=yes; no TOFU. La clave cliente propia tendrá TTL propuesto
de 15 minutos y retirada al salir; su privada vivirá sólo en el temporal del
runner. No se ejecutará `int_bootstrap_db.py`, que inicializa disco y otro alcance.

Consultas con argv fijos: 15 s por comando, 120 s total, 1 MiB para paquetes,
2 MiB total. Primero unidades y templates, procesos por nombre sin argv,
listeners TCP/Unix y `pg_lsclusters --no-header`. **Cualquier cluster**, incluso
down, PostgreSQL activo, listener 5432 o datos inesperados detendrá lo posterior
y conservará el resultado. No psql, pg_isready, SQL, initdb, cambios de servicio,
APT o montajes. Una herramienta ausente conserva su error; no se instala.

Después de esas guardas: os-release sin source/eval, kernel/arquitectura,
dpkg-query con versión/estado, unidades PostgreSQL y template, discos/montajes y
paquetes relevantes para vulnerabilidades, sin contenido de datos. El serial
del arranque registró PostgreSQL/cliente **17.12-0+deb13u1** y el mensaje de
instalación sin inicializar y enmascarada a las 00:36:01 UTC. No demuestra su
estado actual. Una lectura adicional a las 21:09:34 UTC conserva el evento
histórico `Starting postgresql.service` de las 00:34:09 UTC, anterior al mensaje
final del instalador. Ese evento no demuestra un servidor activo ahora ni se
clasifica como prueba de inactividad: las unidades, procesos y clusters deben
comprobarse en el inventario real. CI fija `postgres:18.6-trixie` con digest
`sha256:e3d24f6906d0760bf4da0dae872415391ededefad23fd471c47dc53b0ddf3c42`.
Son versiones mayores distintas; sus pruebas/scans no se atribuyen a esta VM.
GUEST-01 no cambia versiones. Tras autorizar la host key, el siguiente paso es
obtener ese inventario real antes de decidir la preparación de PostgreSQL.
