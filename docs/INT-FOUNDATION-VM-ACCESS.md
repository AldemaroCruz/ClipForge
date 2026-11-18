# Acceso verificable a la VM de fundaciÃ³n INT

RevisiÃ³n documental: **2026-11-18 01:00 UTC** (17 de noviembre en Guatemala).
Estado: **procedimiento propuesto; no ejecutado**. SÃ³lo se leyeron cÃ³digo,
documentaciÃ³n oficial e informes sanitizados. No hubo llamadas GCP, SSH,
lecturas de credenciales/estado completo ni cambios de infraestructura o Git.

El objetivo es autenticar el servidor antes de enviar una credencial de cliente
o un comando a esta VM, conservando OS Login, IAP y la IP privada. La propuesta
no autoriza recuperar el apply parcial, completar IAM, inicializar PostgreSQL,
cargar secretos ni activar la aplicaciÃ³n.

| Identidad que debe permanecer fija | Valor observado en los informes sanitizados |
| --- | --- |
| Proyecto / nÃºmero | `clipforgebeta2` / `816643438938` |
| Zona / nombre | `us-central1-a` / `clipforge-int-base-postgres` |
| Instance ID | `1670495097211408131` |
| CreaciÃ³n | `2026-11-17T16:31:41.095-08:00` |
| Boot disk ID | `2158164599035219715` |
| Data disk ID | `6427691858848206684` |

Estos valores son referencias para nuevos GET, no una lectura cloud realizada
por esta revisiÃ³n. Un nombre o IP iguales no bastan para identificar la VM.

## Hechos y lÃ­mites actuales

El HCL conserva `enable-oslogin=TRUE`, `block-project-ssh-keys=TRUE`,
`disable-legacy-endpoints=TRUE` y `serial-port-enable=FALSE`; no declara
`enable-guest-attributes`. La ausencia en HCL no descarta un valor heredado de
metadata de proyecto: debe comprobarse sin modificarlo.

`startup-final-evidence.json` vincula la lectura serial a esta misma instancia
y no encontrÃ³ huellas SSH. Sus mensajes de instalaciÃ³n/mÃ¡scaras y el marcador de
startup no verifican el estado actual de PostgreSQL, cluster, listener o SCA.
Las polÃ­ticas directas consultadas tampoco contienen los grants previstos de
IAP y actAs para Deploy. No se evaluaron todos los permisos heredados.

`scripts/int_bootstrap_db.py` exige una clave pÃºblica Ed25519 revisada y usa
host-key checking estricto. **No debe ejecutarse como diagnÃ³stico**: inicializa
el disco y transporta secretos. Hace falta un transporte de sÃ³lo lectura con
sus propias comprobaciones, aunque reutilice la misma idea de pin.

## QuÃ© autentica cada mecanismo

| Mecanismo | GarantÃ­a / lÃ­mite para este caso |
| --- | --- |
| OAuth/WIF + GET de Compute | Autentica la consulta al plano de control y permite fijar la identidad de instancia. No devuelve por sÃ­ solo la clave de `sshd`. |
| IAP TCP forwarding | Controla el acceso al tÃºnel de la VM. No sustituye la autenticaciÃ³n SSH del servidor. |
| OS Login, claves o certificados | Autentica/autoriza al **cliente** ante la VM. La CA de OS Login firma la clave del usuario para iniciar sesiÃ³n; no es una CA de host que pueda aÃ±adirse a `known_hosts` como soluciÃ³n. |
| Host key pÃºblica / huella SHA256 por canal independiente | Permite fijar la identidad SSH antes de usar el tÃºnel. Sigue sin ser una atestaciÃ³n de integridad completa del guest. |
| Clave de `ssh-serialport.googleapis.com` | Identifica el gateway serial de Google; no identifica al `sshd` privado de esta VM. |

Los certificados de OS Login tienen vigencia corta y se presentan con
`CertificateFile` en el cliente; no resuelven este bloqueo de servidor.
[Fuente oficial de certificados](https://docs.cloud.google.com/compute/docs/oslogin/certificates).
Para los permisos independientes de OS Login/IAP/actAs, usar el
[contrato oficial de OS Login](https://docs.cloud.google.com/compute/docs/oslogin/set-up-oslogin)
y [el de IAP](https://docs.cloud.google.com/iap/docs/using-tcp-forwarding).

## Primera opciÃ³n: comprobar datos existentes, sÃ³lo lectura

Este paso puede realizarlo posteriormente el coordinador con la sesiÃ³n local
de lectura autorizada; no se ejecutÃ³ aquÃ­.

1. Hacer GET de la VM exacta antes y despuÃ©s de la consulta. Exigir el instance
   ID y creaciÃ³n anteriores, proyecto/zona correctos y discos esperados.
   Extraer Ãºnicamente las claves de metadata pertinentes. Consultar tambiÃ©n
   `enable-guest-attributes` de proyecto si no existe override de instancia.
   Conservar el material completo, si es necesario para revisiÃ³n, sÃ³lo en
   temporal privado; no publicar la metadata completa.
2. Si el alcance existente lo permite, consultar exclusivamente `hostkeys/`
   mediante `instances.getGuestAttributes`, con OAuth y sin token en argv/URL.
   El comando de lectura de referencia es:

   ```text
   gcloud compute instances get-guest-attributes clipforge-int-base-postgres --project=clipforgebeta2 --zone=us-central1-a --query-path=hostkeys/ --format=json
   ```

   Su salida debe capturarse directamente en almacenamiento privado, no en
   logs de Actions o consola compartida. No consultar otros namespaces.
3. Guardar resultado/cÃ³digo/error y fecha. Un403 no autoriza ampliar permisos;
   un404, funciÃ³n deshabilitada o lista vacÃ­a no autoriza activar metadata.
   La API requiere `compute.instances.getGuestAttributes`, permiso distinto de
   `compute.instances.get`. El rol lector de cuatro GET previsto para Deploy
   no contiene el primero. La polÃ­tica efectiva actual debe comprobarse.
4. Si existe exactamente una entrada `hostkeys/ssh-ed25519`, validar su formato
   OpenSSH/Base64 canÃ³nico, tipo y longitud Ed25519, sin comentarios ni saltos
   de lÃ­nea que puedan inyectar entradas en `known_hosts`. Rechazar duplicados,
   entradas contradictorias o identidad de VM cambiante. Calcular su huella
   SHA256 sobre el blob SSH y conservar la clave pÃºblica y huella en el recibo
   privado vinculado a la instancia.
5. Revisar por quÃ© existen esos atributos si no estaban previstos. La respuesta
   no incluye procedencia/fecha por entrada y cualquier proceso dentro del
   guest puede escribir guest attributes. No llamarlos atestaciÃ³n de root ni
   asumir su antigÃ¼edad. SÃ³lo despuÃ©s de resolver esa procedencia puede usarse
   la clave como pin explÃ­cito y comprobar la posesiÃ³n de la clave privada en
   el handshake SSH.

La [API de lectura](https://docs.cloud.google.com/compute/docs/reference/rest/v1/instances/getGuestAttributes)
define namespace/key/value y el permiso. La
[guÃ­a de guest attributes](https://docs.cloud.google.com/compute/docs/metadata/manage-guest-attributes)
explica los permisos, escritores dentro del guest y la integraciÃ³n automÃ¡tica
SSH cuando OS Login estÃ¡ deshabilitado. AquÃ­ se conserva OS Login y se propone
una consulta/pin explÃ­citos; no se promete autocarga de claves por gcloud.

## Si no hay clave publicada: cambio operativo pendiente de aprobaciÃ³n

**RecomendaciÃ³n mÃ­nima para revisar, no ejecutar:** publicar una sola vez la
clave **pÃºblica existente** hacia serial port1 mediante un startup temporal.
Evita habilitar guest attributes, serial interactivo o contraseÃ±as locales.
Necesita aprobaciÃ³n expresa de los bytes del publicador, metadata temporal y
parada/arranque de la VM; no es una operaciÃ³n de sÃ³lo lectura cloud.

El cambio concreto propuesto es Ã©ste:

1. Capturar privadamente el mapa de metadata actual y su fingerprint de
   concurrencia. Exigir que `startup-script` coincida byte por byte con
   `postgres-install.sh`, SHA256
   `a93bd662abce93b12c6389a37fccca49612ef3d1ee83eb882051cd5489daf255`.
   Comprobar, sin imprimirlo, que no hay otro `startup-script-url` efectivo de
   instancia/proyecto u otro lanzador que pueda ejecutar acciones al arrancar.
   Si hay diferencias, detenerse; no sobrescribirlas.
2. Preparar y revisar un publicador autÃ³nomo Python3 de una sola finalidad.
   Su contrato debe quedar fijado por SHA256 antes de la aprobaciÃ³n:
   - constantes de proyecto, zona, instance ID y un nonce pÃºblico de esta
     intervenciÃ³n;
   - GET de esas identidades desde metadata, sin consultar tokens;
   - apertura sÃ³lo de `/etc/ssh/ssh_host_ed25519_key.pub`, regular, root-owned,
     sin escritura de grupo/otros, sin symlinks y con tamaÃ±o mÃ¡ximo de 1024 bytes;
     comprobar tambiÃ©n el directorio `/etc/ssh` y el formato del blob;
   - si falta la `.pub`, fallar: no leer la clave privada ni generarla o rotarla;
   - emitir una Ãºnica lÃ­nea acotada con marcador, nonce, instance ID,
     `ssh-ed25519 <blob>` y huella SHA256 hacia `/dev/ttyS0` (serial port1),
     sin volcar entorno, archivos, logs o errores sensibles;
   - no APT, SQL, Secret Manager, disco de datos, cambios de usuario/SSH ni
     llamadas externas. Errores limitados a cÃ³digos fijos.
3. Sustituir provisionalmente **sÃ³lo el valor de `startup-script` de esa VM**,
   usando fingerprint de metadata para detectar concurrencia y preservando
   todas las demÃ¡s claves. No tocar metadata de proyecto, OS Login,
   `serial-port-enable`, guest attributes, firewall o IAM. El publicador
   sustituye al instalador durante ese arranque; no lo envuelve ni lo repite.
4. En ventana aprobada, parada/arranque controlados de la misma VM; sin reset
   forzado, reemplazo, imagen nueva, detach, formato ni recreaciÃ³n. Comprobar
   de nuevo instance ID y ambos discos. La parada/arranque produce interrupciÃ³n
   y escrituras normales del SO; no equivale a una inspecciÃ³n sin cambios.
5. Obtener por OAuth el serial port1 en memoria/temporal privado. Exigir un
   registro Ãºnico con el nonce, identidad y clave vÃ¡lidos; los mensajes
   genÃ©ricos de generaciÃ³n de hostkeys no bastan. Vincular GET de VM antes y
   despuÃ©s y no publicar el log completo. Un fallo o registro ausente conserva
   el bloqueo y no dispara otro reinicio automÃ¡tico.
6. Restaurar los bytes originales de `startup-script`, preservando cualquier
   otra metadata y usando el fingerprint nuevo. Verificar hash/identidad de
   nuevo. No reiniciar otra vez para comprobar la restauraciÃ³n. Si no puede
   restaurarse, informar la metadata temporal pendiente y bloquear promociÃ³n.

Google documenta que el [startup corre como root al arrancar y publica salida serial](https://docs.cloud.google.com/compute/docs/instances/startup-scripts/linux).
[`setMetadata`](https://docs.cloud.google.com/compute/docs/reference/rest/v1/instances/setMetadata)
usa fingerprint para concurrencia; el mapa no debe reconstruirse sÃ³lo desde
las cuatro claves conocidas. El
[GET serial autenticado](https://docs.cloud.google.com/compute/docs/reference/rest/v1/instances/getSerialPortOutput)
no exige habilitar la consola interactiva. La publicaciÃ³n propuesta es una
inferencia de estos mecanismos, **no una funciÃ³n de host-key attestation
administrada por Google ni un procedimiento ya probado**.

No se debe reusar un plan anterior para introducir este cambio. Es metadata
gestionada por Terraform y el startup temporal altera una entrada revisada:
deben registrarse la decisiÃ³n, cambio/restauraciÃ³n y su reconciliaciÃ³n antes de
cualquier plan/apply posterior. No modificar estado ni importar recursos como
parte de obtener una host key. La ejecuciÃ³n del publicador todavÃ­a requiere
implementaciÃ³n revisada y una autorizaciÃ³n operativa separada.

## Alternativas descartadas o con mayor alcance

| Alternativa | Motivo / cambio necesario |
| --- | --- |
| Activar guest attributes y reiniciar simplemente | No garantiza publicar una clave ya generada. El firstboot guarda el instance ID y omite la inicializaciÃ³n cuando sigue siendo el mismo. No borrar esa marca: puede regenerar hostkeys. |
| Publicador explÃ­cito a guest attributes | Requiere `enable-guest-attributes=TRUE` en esta VM y publicar desde el guest, ademÃ¡s del canal de ejecuciÃ³n/reinicio. AmplÃ­a metadata legible/escribible desde procesos del guest y no evita revisar procedencia. No aporta ventaja mÃ­nima frente al publicador serial propuesto. |
| Consola serial interactiva | Requiere cambiar `serial-port-enable` y resolver autenticaciÃ³n local del guest. Las imÃ¡genes Linux no traen normalmente contraseÃ±as locales; no crear/resetear passwords, usar autologin root ni deshabilitar OS Login para este fin. |
| Certificados de host propios | RequerirÃ­an una CA/polÃ­tica de confianza, emisiÃ³n y configuraciÃ³n `HostCertificate` del servidor. No existen demostrados en este incremento; la CA de usuario OS Login no sustituye ese diseÃ±o. |
| Keyscan solo, `accept-new`, `StrictHostKeyChecking=no` | Descubren/aceptan la clave por la misma conexiÃ³n; no establecen confianza independiente. No permitidos. |
| Copiar clave del disco mediante VM/snapshot de rescate | Crea recursos o cambia adjuntos/alcance de disco. Fuera de esta propuesta mÃ­nima. |

El [cÃ³digo oficial firstboot](https://github.com/GoogleCloudPlatform/google-guest-agent/blob/7375d32a516c0a37c143ec514033bdee8c504428/cmd/core_plugin/firstboot/firstboot.go)
comprueba/persiste instance ID antes del setup. Su
[implementaciÃ³n Linux](https://github.com/GoogleCloudPlatform/google-guest-agent/blob/7375d32a516c0a37c143ec514033bdee8c504428/cmd/core_plugin/firstboot/firstboot_linux.go)
genera con `ssh-keygen -q`, descarta salida y publica el valor en guest attributes;
el INFO sÃ³lo muestra tipo/ruta. Es fuente identificada para razonar sobre la
limitaciÃ³n, no evidencia de la versiÃ³n instalada en esta VM. La
[guÃ­a serial](https://docs.cloud.google.com/compute/docs/troubleshooting/troubleshooting-using-serial-console)
separa acceso al gateway de login local y documenta la necesidad de contraseÃ±a
para esa vÃ­a. No ejecutar sus recetas de creaciÃ³n de usuarios.

## ConexiÃ³n posterior y cierre de evidencia

Una vez obtenido el pin por un canal aceptado y comprobados los permisos
existentes, crear `known_hosts` con modo 0600 en scratch con modo 0700 y alias vinculado al ID,
por ejemplo `clipforge-int-base-postgres.1670495097211408131`. Forzar
`HostKeyAlias` a ese alias, `StrictHostKeyChecking=yes`, `UserKnownHostsFile` al
archivo propio, `HostKeyAlgorithms=ssh-ed25519`, `UpdateHostKeys=no`, modo batch,
sin password/keyboard-interactive ni agent forwarding. No consultar/importar
known_hosts o llaves personales. La clave efÃ­mera de **cliente** pertenece a
esta intervenciÃ³n y no sustituye el pin del **servidor**.

Con IAP, un keyscan acotado a loopback puede obtener una candidata para
compararla con una huella SHA256 independiente ya autenticada. No debe iniciar
login ni guardar esa candidata como confiable antes de comparar. Si ya se
obtuvo la clave completa por el canal confiable, el handshake SSH con pin
estricto verifica directamente su posesiÃ³n y keyscan es innecesario.

El SDK local leÃ­do es **582.0.0**; `command_lib/compute/ssh_utils.py` tiene SHA256
`7b16059b5100df1579b8b4cec3dffa0e4e4c2c6f4fde9395a33d7297f0156e43`.
Su configuraciÃ³n puede elegir `StrictHostKeyChecking=no` si no recibe clave o
alias conocido: por ello no confiar en defaults. No se ejecutÃ³ el SDK contra
GCP en esta revisiÃ³n. El pin explÃ­cito sigue la
[recomendaciÃ³n oficial de obtener hostkeys por canal independiente](https://docs.cloud.google.com/compute/docs/connect/ssh-best-practices/credentials).

Conservar privadamente: identidad/fecha, respuesta GET y errores acotados,
procedencia del pin, clave pÃºblica/huella, hashes del publicador y de metadata
original/restaurada si se aprueban, y resultado del handshake. Publicar sÃ³lo
estado por fase y referencias/hashes seguros. No publicar serial completo,
credenciales, entorno, estado Terraform o planes completos.

Un handshake correcto habilita Ãºnicamente las verificaciones autorizadas de
PG masked/inactivo, cluster/listener ausentes e inventario/SCA propio. No
demuestra TLS, restore, autenticaciÃ³n SQL o preparaciÃ³n de runtime. Si falta
host key, permisos IAP/actAs efectivos o procedencia revisada, detenerse con ese
bloqueo concreto; ningÃºn paso de este documento los concede automÃ¡ticamente.

## Lecturas actuales del coordinador durante la recuperación

La consulta autenticada posterior de la instancia1670495097211408131 y
`getGuestAttributes?queryPath=hostkeys/` devolvió **404: hostkeys/ no encontrado**.
No hay enable-guest-attributes en instancia ni proyecto; tampoco startup-script
o startup-script-url de proyecto en la lectura. No se obtuvo un pin ni se
modificó metadata, IAM, OS Login, VM o discos. El publicador/reinicio descritos
arriba siguen siendo sólo una propuesta que requiere revisión de sus bytes y
autorización operativa separada. El gestor manual del bootstrap fue confirmado
por el propietario; eso no autentica una clave SSH aún no publicada.
