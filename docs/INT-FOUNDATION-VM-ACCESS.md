# Acceso verificable a la VM de fundación INT

Revisión documental: **2026-11-18 01:00 UTC** (17 de noviembre en Guatemala).
Estado: **procedimiento propuesto; no ejecutado**. Sólo se leyeron código,
documentación oficial e informes sanitizados. No hubo llamadas GCP, SSH,
lecturas de credenciales/estado completo ni cambios de infraestructura o Git.

El objetivo es autenticar el servidor antes de enviar una credencial de cliente
o un comando a esta VM, conservando OS Login, IAP y la IP privada. La propuesta
no autoriza recuperar el apply parcial, completar IAM, inicializar PostgreSQL,
cargar secretos ni activar la aplicación.

| Identidad que debe permanecer fija | Valor observado en los informes sanitizados |
| --- | --- |
| Proyecto / número | `clipforgebeta2` / `816643438938` |
| Zona / nombre | `us-central1-a` / `clipforge-int-base-postgres` |
| Instance ID | `1670495097211408131` |
| Creación | `2026-11-17T16:31:41.095-08:00` |
| Boot disk ID | `2158164599035219715` |
| Data disk ID | `6427691858848206684` |

Estos valores son referencias para nuevos GET, no una lectura cloud realizada
por esta revisión. Un nombre o IP iguales no bastan para identificar la VM.

## Hechos y límites actuales

El HCL conserva `enable-oslogin=TRUE`, `block-project-ssh-keys=TRUE`,
`disable-legacy-endpoints=TRUE` y `serial-port-enable=FALSE`; no declara
`enable-guest-attributes`. La ausencia en HCL no descarta un valor heredado de
metadata de proyecto: debe comprobarse sin modificarlo.

`startup-final-evidence.json` vincula la lectura serial a esta misma instancia
y no encontró huellas SSH. Sus mensajes de instalación/máscaras y el marcador de
startup no verifican el estado actual de PostgreSQL, cluster, listener o SCA.
Las políticas directas consultadas tampoco contienen los grants previstos de
IAP y actAs para Deploy. No se evaluaron todos los permisos heredados.

`scripts/int_bootstrap_db.py` exige una clave pública Ed25519 revisada y usa
host-key checking estricto. **No debe ejecutarse como diagnóstico**: inicializa
el disco y transporta secretos. Hace falta un transporte de sólo lectura con
sus propias comprobaciones, aunque reutilice la misma idea de pin.

## Qué autentica cada mecanismo

| Mecanismo | Garantía / límite para este caso |
| --- | --- |
| OAuth/WIF + GET de Compute | Autentica la consulta al plano de control y permite fijar la identidad de instancia. No devuelve por sí solo la clave de `sshd`. |
| IAP TCP forwarding | Controla el acceso al túnel de la VM. No sustituye la autenticación SSH del servidor. |
| OS Login, claves o certificados | Autentica/autoriza al **cliente** ante la VM. La CA de OS Login firma la clave del usuario para iniciar sesión; no es una CA de host que pueda añadirse a `known_hosts` como solución. |
| Host key pública / huella SHA256 por canal independiente | Permite fijar la identidad SSH antes de usar el túnel. Sigue sin ser una atestación de integridad completa del guest. |
| Clave de `ssh-serialport.googleapis.com` | Identifica el gateway serial de Google; no identifica al `sshd` privado de esta VM. |

Los certificados de OS Login tienen vigencia corta y se presentan con
`CertificateFile` en el cliente; no resuelven este bloqueo de servidor.
[Fuente oficial de certificados](https://docs.cloud.google.com/compute/docs/oslogin/certificates).
Para los permisos independientes de OS Login/IAP/actAs, usar el
[contrato oficial de OS Login](https://docs.cloud.google.com/compute/docs/oslogin/set-up-oslogin)
y [el de IAP](https://docs.cloud.google.com/iap/docs/using-tcp-forwarding).

## Primera opción: comprobar datos existentes, sólo lectura

Este paso puede realizarlo posteriormente el coordinador con la sesión local
de lectura autorizada; no se ejecutó aquí.

1. Hacer GET de la VM exacta antes y después de la consulta. Exigir el instance
   ID y creación anteriores, proyecto/zona correctos y discos esperados.
   Extraer únicamente las claves de metadata pertinentes. Consultar también
   `enable-guest-attributes` de proyecto si no existe override de instancia.
   Conservar el material completo, si es necesario para revisión, sólo en
   temporal privado; no publicar la metadata completa.
2. Si el alcance existente lo permite, consultar exclusivamente `hostkeys/`
   mediante `instances.getGuestAttributes`, con OAuth y sin token en argv/URL.
   El comando de lectura de referencia es:

   ```text
   gcloud compute instances get-guest-attributes clipforge-int-base-postgres --project=clipforgebeta2 --zone=us-central1-a --query-path=hostkeys/ --format=json
   ```

   Su salida debe capturarse directamente en almacenamiento privado, no en
   logs de Actions o consola compartida. No consultar otros namespaces.
3. Guardar resultado/código/error y fecha. Un403 no autoriza ampliar permisos;
   un404, función deshabilitada o lista vacía no autoriza activar metadata.
   La API requiere `compute.instances.getGuestAttributes`, permiso distinto de
   `compute.instances.get`. El rol lector de cuatro GET previsto para Deploy
   no contiene el primero. La política efectiva actual debe comprobarse.
4. Si existe exactamente una entrada `hostkeys/ssh-ed25519`, validar su formato
   OpenSSH/Base64 canónico, tipo y longitud Ed25519, sin comentarios ni saltos
   de línea que puedan inyectar entradas en `known_hosts`. Rechazar duplicados,
   entradas contradictorias o identidad de VM cambiante. Calcular su huella
   SHA256 sobre el blob SSH y conservar la clave pública y huella en el recibo
   privado vinculado a la instancia.
5. Revisar por qué existen esos atributos si no estaban previstos. La respuesta
   no incluye procedencia/fecha por entrada y cualquier proceso dentro del
   guest puede escribir guest attributes. No llamarlos atestación de root ni
   asumir su antigüedad. Sólo después de resolver esa procedencia puede usarse
   la clave como pin explícito y comprobar la posesión de la clave privada en
   el handshake SSH.

La [API de lectura](https://docs.cloud.google.com/compute/docs/reference/rest/v1/instances/getGuestAttributes)
define namespace/key/value y el permiso. La
[guía de guest attributes](https://docs.cloud.google.com/compute/docs/metadata/manage-guest-attributes)
explica los permisos, escritores dentro del guest y la integración automática
SSH cuando OS Login está deshabilitado. Aquí se conserva OS Login y se propone
una consulta/pin explícitos; no se promete autocarga de claves por gcloud.

## Si no hay clave publicada: cambio operativo pendiente de aprobación

**Recomendación mínima para revisar, no ejecutar:** publicar una sola vez la
clave **pública existente** hacia serial port1 mediante un startup temporal.
Evita habilitar guest attributes, serial interactivo o contraseñas locales.
Necesita aprobación expresa de los bytes del publicador, metadata temporal y
parada/arranque de la VM; no es una operación de sólo lectura cloud.

El cambio concreto propuesto es éste:

1. Capturar privadamente el mapa de metadata actual y su fingerprint de
   concurrencia. Exigir que `startup-script` coincida byte por byte con
   `postgres-install.sh`, SHA256
   `a93bd662abce93b12c6389a37fccca49612ef3d1ee83eb882051cd5489daf255`.
   Comprobar, sin imprimirlo, que no hay otro `startup-script-url` efectivo de
   instancia/proyecto u otro lanzador que pueda ejecutar acciones al arrancar.
   Si hay diferencias, detenerse; no sobrescribirlas.
2. Preparar y revisar un publicador autónomo Python3 de una sola finalidad.
   Su contrato debe quedar fijado por SHA256 antes de la aprobación:
   - constantes de proyecto, zona, instance ID y un nonce público de esta
     intervención;
   - GET de esas identidades desde metadata, sin consultar tokens;
   - apertura sólo de `/etc/ssh/ssh_host_ed25519_key.pub`, regular, root-owned,
     sin escritura de grupo/otros, sin symlinks y con tamaño máximo de 1024 bytes;
     comprobar también el directorio `/etc/ssh` y el formato del blob;
   - si falta la `.pub`, fallar: no leer la clave privada ni generarla o rotarla;
   - emitir una única línea acotada con marcador, nonce, instance ID,
     `ssh-ed25519 <blob>` y huella SHA256 hacia `/dev/ttyS0` (serial port1),
     sin volcar entorno, archivos, logs o errores sensibles;
   - no APT, SQL, Secret Manager, disco de datos, cambios de usuario/SSH ni
     llamadas externas. Errores limitados a códigos fijos.
3. Sustituir provisionalmente **sólo el valor de `startup-script` de esa VM**,
   usando fingerprint de metadata para detectar concurrencia y preservando
   todas las demás claves. No tocar metadata de proyecto, OS Login,
   `serial-port-enable`, guest attributes, firewall o IAM. El publicador
   sustituye al instalador durante ese arranque; no lo envuelve ni lo repite.
4. En ventana aprobada, parada/arranque controlados de la misma VM; sin reset
   forzado, reemplazo, imagen nueva, detach, formato ni recreación. Comprobar
   de nuevo instance ID y ambos discos. La parada/arranque produce interrupción
   y escrituras normales del SO; no equivale a una inspección sin cambios.
5. Obtener por OAuth el serial port1 en memoria/temporal privado. Exigir un
   registro único con el nonce, identidad y clave válidos; los mensajes
   genéricos de generación de hostkeys no bastan. Vincular GET de VM antes y
   después y no publicar el log completo. Un fallo o registro ausente conserva
   el bloqueo y no dispara otro reinicio automático.
6. Restaurar los bytes originales de `startup-script`, preservando cualquier
   otra metadata y usando el fingerprint nuevo. Verificar hash/identidad de
   nuevo. No reiniciar otra vez para comprobar la restauración. Si no puede
   restaurarse, informar la metadata temporal pendiente y bloquear promoción.

Google documenta que el [startup corre como root al arrancar y publica salida serial](https://docs.cloud.google.com/compute/docs/instances/startup-scripts/linux).
[`setMetadata`](https://docs.cloud.google.com/compute/docs/reference/rest/v1/instances/setMetadata)
usa fingerprint para concurrencia; el mapa no debe reconstruirse sólo desde
las cuatro claves conocidas. El
[GET serial autenticado](https://docs.cloud.google.com/compute/docs/reference/rest/v1/instances/getSerialPortOutput)
no exige habilitar la consola interactiva. La publicación propuesta es una
inferencia de estos mecanismos, **no una función de host-key attestation
administrada por Google ni un procedimiento ya probado**.

No se debe reusar un plan anterior para introducir este cambio. Es metadata
gestionada por Terraform y el startup temporal altera una entrada revisada:
deben registrarse la decisión, cambio/restauración y su reconciliación antes de
cualquier plan/apply posterior. No modificar estado ni importar recursos como
parte de obtener una host key. Los ejecutables propuestos abajo se probaron
con dobles locales; su ejecución real requiere revisión de sus bytes y una
autorización operativa separada.

## Alternativas descartadas o con mayor alcance

| Alternativa | Motivo / cambio necesario |
| --- | --- |
| Activar guest attributes y reiniciar simplemente | No garantiza publicar una clave ya generada. El firstboot guarda el instance ID y omite la inicialización cuando sigue siendo el mismo. No borrar esa marca: puede regenerar hostkeys. |
| Publicador explícito a guest attributes | Requiere `enable-guest-attributes=TRUE` en esta VM y publicar desde el guest, además del canal de ejecución/reinicio. Amplía metadata legible/escribible desde procesos del guest y no evita revisar procedencia. No aporta ventaja mínima frente al publicador serial propuesto. |
| Consola serial interactiva | Requiere cambiar `serial-port-enable` y resolver autenticación local del guest. Las imágenes Linux no traen normalmente contraseñas locales; no crear/resetear passwords, usar autologin root ni deshabilitar OS Login para este fin. |
| Certificados de host propios | Requerirían una CA/política de confianza, emisión y configuración `HostCertificate` del servidor. No existen demostrados en este incremento; la CA de usuario OS Login no sustituye ese diseño. |
| Keyscan solo, `accept-new`, `StrictHostKeyChecking=no` | Descubren/aceptan la clave por la misma conexión; no establecen confianza independiente. No permitidos. |
| Copiar clave del disco mediante VM/snapshot de rescate | Crea recursos o cambia adjuntos/alcance de disco. Fuera de esta propuesta mínima. |

El [código oficial firstboot](https://github.com/GoogleCloudPlatform/google-guest-agent/blob/7375d32a516c0a37c143ec514033bdee8c504428/cmd/core_plugin/firstboot/firstboot.go)
comprueba/persiste instance ID antes del setup. Su
[implementación Linux](https://github.com/GoogleCloudPlatform/google-guest-agent/blob/7375d32a516c0a37c143ec514033bdee8c504428/cmd/core_plugin/firstboot/firstboot_linux.go)
genera con `ssh-keygen -q`, descarta salida y publica el valor en guest attributes;
el INFO sólo muestra tipo/ruta. Es fuente identificada para razonar sobre la
limitación, no evidencia de la versión instalada en esta VM. La
[guía serial](https://docs.cloud.google.com/compute/docs/troubleshooting/troubleshooting-using-serial-console)
separa acceso al gateway de login local y documenta la necesidad de contraseña
para esa vía. No ejecutar sus recetas de creación de usuarios.

## Conexión posterior y cierre de evidencia

Una vez obtenido el pin por un canal aceptado y comprobados los permisos
existentes, crear `known_hosts` con modo 0600 en scratch con modo 0700 y alias vinculado al ID,
por ejemplo `clipforge-int-base-postgres.1670495097211408131`. Forzar
`HostKeyAlias` a ese alias, `StrictHostKeyChecking=yes`, `UserKnownHostsFile` al
archivo propio, `HostKeyAlgorithms=ssh-ed25519`, `UpdateHostKeys=no`, modo batch,
sin password/keyboard-interactive ni agent forwarding. No consultar/importar
known_hosts o llaves personales. La clave efímera de **cliente** pertenece a
esta intervención y no sustituye el pin del **servidor**.

Con IAP, un keyscan acotado a loopback puede obtener una candidata para
compararla con una huella SHA256 independiente ya autenticada. No debe iniciar
login ni guardar esa candidata como confiable antes de comparar. Si ya se
obtuvo la clave completa por el canal confiable, el handshake SSH con pin
estricto verifica directamente su posesión y keyscan es innecesario.

El SDK local leído es **582.0.0**; `command_lib/compute/ssh_utils.py` tiene SHA256
`7b16059b5100df1579b8b4cec3dffa0e4e4c2c6f4fde9395a33d7297f0156e43`.
Su configuración puede elegir `StrictHostKeyChecking=no` si no recibe clave o
alias conocido: por ello no confiar en defaults. No se ejecutó el SDK contra
GCP en esta revisión. El pin explícito sigue la
[recomendación oficial de obtener hostkeys por canal independiente](https://docs.cloud.google.com/compute/docs/connect/ssh-best-practices/credentials).

Conservar privadamente: identidad/fecha, respuesta GET y errores acotados,
procedencia del pin, clave pública/huella, hashes del publicador y de metadata
original/restaurada si se aprueban, y resultado del handshake. Publicar sólo
estado por fase y referencias/hashes seguros. No publicar serial completo,
credenciales, entorno, estado Terraform o planes completos.

Un handshake correcto habilita únicamente las verificaciones autorizadas de
PG masked/inactivo, cluster/listener ausentes e inventario/SCA propio. No
demuestra TLS, restore, autenticación SQL o preparación de runtime. Si falta
host key, permisos IAP/actAs efectivos o procedencia revisada, detenerse con ese
bloqueo concreto; ningún paso de este documento los concede automáticamente.

## Lecturas actuales del coordinador durante la recuperación

La consulta autenticada posterior de la instancia1670495097211408131 y
`getGuestAttributes?queryPath=hostkeys/` devolvió **404: hostkeys/ no encontrado**.
No hay enable-guest-attributes en instancia ni proyecto; tampoco startup-script
o startup-script-url de proyecto en la lectura. No se obtuvo un pin ni se
modificó metadata, IAM, OS Login, VM o discos. El publicador/reinicio descritos
arriba siguen siendo sólo una propuesta que requiere revisión de sus bytes y
autorización operativa separada. El gestor manual del bootstrap fue confirmado
por el propietario; eso no autentica una clave SSH aún no publicada.

## Ejecutables propuestos, sin ejecución cloud

Archivos: `scripts/int_vm_hostkey.py`, `scripts/int_vm_hostkey_guest.py` y
`tests/test_int_vm_hostkey.py`, con LF. Conservar también el startup versionado
original al empaquetar: el operador exige su SHA256 conocido. No se ejecutó
contra GCP/VM ni se añadió un grant o excepción de scanner. El operador obtiene
OAuth del usuario gcloud activo habitual; rechaza ADC, impersonación y overrides,
sin leer directamente sus archivos de credenciales. No ejecuta SSH.

```text
python -B -m scripts.int_vm_hostkey
python -B -m scripts.int_vm_hostkey check
python -B -m unittest tests.test_int_vm_hostkey -v
```

Los dos primeros sólo verifican fuentes/hashes offline. Los tests simulan HTTP,
operaciones y guest. En Windows se exige ACL limitada al usuario actual,
SYSTEM y Administrators; en POSIX, directorio propio con modo0700. No se cambian
ACL. El scratch debe estar fuera del árbol de fuentes; su padre ya debe ser
privado. Los archivos se crean sin sobrescribir contenido existente.

Después, sólo bajo autorización de lectura aplicable, puede prepararse una
propuesta con un directorio nuevo bajo el padre privado revisado:

```text
python -B -m scripts.int_vm_hostkey inspect --workdir <directorio-privado-nuevo>
python -B -m scripts.int_vm_hostkey check --workdir <directorio-privado>
```

`inspect` hace sólo GET de proyecto, VM y ambos discos, fija sus IDs/imagen,
comprueba IP privada y startup original. Rechaza `shutdown-script`,
`shutdown-script-url` y `startup-script-url` en **instancia y proyecto**, aun
vacíos, además de startup heredado de proyecto. Prepara `proposal.json`,
`publisher.py` ligado a nonce/hash y `journal.json` privados. El publisher lee
su propio source para emitir el hash exacto de sus bytes junto al pin.
`proposal.json` contiene sólo identidad pública, nonce, hashes, workdir,
cuenta operadora, `lastStartTimestamp` y flags sanitizados de los hooks por
scope; no contiene sus valores, el mapa de metadata, serial o credenciales.
También fija SHA256 del mapa inicial de metadata de instancia: si cambia antes
de ejecutar, exige nueva inspección/revisión sin enviar un POST.

La autorización futura será `<workdir>/owner-authorization.json`, revisada
externamente y con SHA256 entregado por separado. El operador no la genera;
escribir un campo `decision` no sustituye el consentimiento del propietario.
El objeto debe contener exactamente:

| Campo | Valor exigido |
| --- | --- |
| `schema` | `clipforge-int-hostkey-owner-authorization-1` |
| `decision` | `authorize_hostkey_recovery_once` |
| `authorized_by` | `admin@ixbalam.studio` |
| `authorization_id` | Identificador revisado de entre8 y100 caracteres alfanuméricos, `_` o `-` |
| `approved_at`, `expires_at` | Timestamps con zona, ventana positiva de máximo dos horas y vigente en cada POST |
| `proposal` | Copia exacta de `proposal.json`: hashes de ambos scripts/payload, nonce, workdir e identidades fijas |

Únicamente tras esa autorización específica futura:

```text
python -B -m scripts.int_vm_hostkey execute --workdir <directorio-privado> --authorization <directorio-privado>/owner-authorization.json --authorization-sha256 <sha256-revisado>
```

Cada intención se persiste antes de su único POST, con `requestId` determinista
por fase. Se exige DONE sin error, tipo, nombre/ID numérico, target VM ID, zona
y `clientOperationId` exactos. Polling limitado a180s por fase, timeout HTTP30s.
RUNNING o HTTP200 no bastan. Sólo hay un stop/start posible; se comprueban
metadata/hooks entre fases. Un412 no produce reintento automático.

La restauración exige que el **startup actual completo** siga siendo el
publisher propio exacto, además de fingerprint fresco para CAS. Cambia sólo
esa entrada del mapa **actual**, conservando entradas ajenas. No sobrescribe un
startup alterado por otro actor. Exige start terminado, VM RUNNING en un nuevo
arranque estable y un registro serial completo/único con nonce, identidad y hash
exactos. No restaura el instalador PG en un manejador de excepciones.
El GET serial solicitado desde 0 debe devolver `start` válido normalizado a 0:
un buffer truncado o un offset ausente/inválido bloquean publicación y
restauración aunque contengan un registro correcto. La restauración anterior
al ciclo vuelve a comprobar RUNNING y el timestamp inicial **después** de
terminar la operación; si cambiaron, no declara `restored_before_cycle_no_pin`.

### Recuperación tras interrupción

```text
python -B -m scripts.int_vm_hostkey recover --workdir <directorio-privado> --authorization <directorio-privado>/owner-authorization.json --authorization-sha256 <sha256-revisado> [--operation-name <nombre-exacto-obtenido-por-canal-autenticado>]
```

Requiere autorización vigente para su posible restauración, incluida una
renovación expresamente revisada si venció la original. Nunca instala otro
publisher, hace stop/start ni consulta listas genéricas de operaciones.

| Interrupción | Comportamiento |
| --- | --- |
| Metadata instalada, sin intención stop/start | Sólo restaura tras metadata DONE correcta, VM RUNNING y mismo arranque original. No obtiene pin. |
| Stop enviado/indeterminado, sin start registrado | Conserva publisher y se detiene. No restaura el instalador ni arranca; requiere decisión posterior. |
| Start enviado, respuesta perdida/timeout | Conserva publisher. Sólo GET/poll de operación conocida; si se perdió el nombre, requiere obtenerlo por lectura autenticada. Valida requestId/tipo/target/ID. |
| Start DONE, publicación ausente | Espera dentro del límite y falla conservando publisher. No inicia otro ciclo. |
| Registro correcto, respuesta restore perdida | Confirma esa operación y startup original actual; no repite POST ni reinicia. |
| Startup ajeno, IDs cambiados, operación con error o arranque concurrente | Bloquea sin sobrescribir ni reiniciar. |

Una respuesta perdida no se interpreta como fallo sin efectos. No borrar el
journal para repetir `execute`: sólo admite fase inicial sin operaciones.
`operator.lock` es un archivo local con lock del SO liberado al terminar el
proceso, incluso tras interrupción; no borrar ni forzar desbloqueos cloud.
El journal conserva operaciones, autorizaciones y fase sin serial completo ni
credenciales. No hay rollback automático por error.

Tras completar y restaurar, se crea `known_hosts` privado con alias por instance
ID y se informa la huella. `ssh_options()` entrega las opciones estrictas
descritas arriba; no realiza conexión. Su existencia no demuestra SSH/IAP
efectivo. Las regresiones locales no acreditan startup real del publisher,
recuperación en GCP, inventario/SCA ni PostgreSQL operativo.

### Corrección de identidad de proyecto comprobada por el coordinador

El primer `inspect` real se bloqueó en `project_identity`, sin POST ni
propuesta creada. El fixture confundía `Compute Project.id` con el número de
Resource Manager. El coordinador contrastó por GET autenticados:
Compute `id=4183880808888199084`, `name=clipforgebeta2` y selfLink exacto de ese
proyecto; Resource Manager v1 `projectId=clipforgebeta2`,
`projectNumber=816643438938`, `lifecycleState=ACTIVE`.

La corrección fija el **ID interno Compute exacto**, name y selfLink; no elimina
la validación ni agrega otro transporte/API. El guard conserva el número
Resource Manager y el publisher lo exige desde IMDS. Una regresión comprueba
que sustituir el ID Compute por el número Resource Manager falla antes de POST.
La [referencia oficial Compute Project](https://docs.cloud.google.com/compute/docs/reference/rest/v1/projects)
define `id` como identificador interno de Compute y `name` como project ID;
el [recurso Resource Manager v1](https://docs.cloud.google.com/resource-manager/reference/rest/v1/projects)
define por separado `projectNumber`. Esta corrección no escribe en la VM.
