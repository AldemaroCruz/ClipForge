# INT: CVE-2026-6653 en el runtime revisado

Estado: **bloqueante, registrado y no aceptado**. Esta revisión no aprueba INT,
release, despliegue ni excepciones. Consulta de fuentes y probes de solo lectura:
2026-11-14 UTC, desde las 00:06; corresponde todavía al 2026-11-13 en Guatemala.
Responsable propuesto para seguimiento y decisión: **AldemaroCruz, propietario**;
la asignación requiere confirmación. Vigencia de esta revisión: **2026-11-27**.
Al vencer, o aparecer un fix/cambio de imagen antes, se debe revisar nuevamente;
la vigencia no permite ejecutar infraestructura ni aceptar el riesgo.

## Componente e identidad exacta

Se reutilizaron `reports/runtime-v4-trivy.json` y
`runtime-inventory/runtime-v4-independent-{inventory,comparison}.json` del
expediente externo
`C:\Users\itres\AppData\Local\ClipForge\int-e2e01\run-5eadef4f19484d988431dad6558740d7`.
No se volvió a construir ni escanear la imagen.

| Identidad | Valor |
| --- | --- |
| Manifest OCI | `sha256:d4b65631b30c26785ae18898cd826990fa20b4dce45015fb241ba108ddba7d49` |
| Config OCI examinada por Trivy | `sha256:3a4f5aa912fe8f12ca1ff67b9c7aa4391b9f23643b17872cf21da1a06659ee9f` |
| Imagen local equivalente usada en probes | `sha256:7ef5a28a3fd02b73e1b6b90ba0e7a0be7c0f342dcc7d116bd6a081d58723b107` |
| SO / paquete | Debian 13.7; `libxml2 2.12.7+dfsg+really2.9.14-2.1+deb13u3`, amd64 |
| Finding conservado | `CVE-2026-6653`, CRITICAL, `Status=affected`, sin `FixedVersion` |

La comparación previa verifica igualdad del JSON completo de configuración y
los 12 DiffIDs; la serialización genera IDs diferentes. No se atribuye evidencia
de otras imágenes. El finding proviene del target Debian y usa severidad NVD;
los metadatos Python sin HIGH/CRITICAL no lo resuelven ni cubren todos los ELF
vendorizados.

## Fix disponible en la misma distribución

El [tracker oficial de Debian para esta CVE](https://security-tracker.debian.org/tracker/CVE-2026-6653)
mantiene exactamente la versión instalada de trixie como vulnerable y marca
`no-dsa`/minor issue. Esto describe la decisión de Debian: no cambia el CRITICAL
del gate ni constituye una aceptación de ClipForge.
La [página oficial del paquete trixie](https://packages.debian.org/trixie/libxml2)
publica la misma versión instalada; no se verificó un reemplazo oficial de
trixie corregido para proponer un cambio de pin mínimo.

Debian registra la primera versión corregida de unstable como
`2.14.5+dfsg-0.1` y forky/sid actuales como corregidos. Esos paquetes no se
presentan como fixes compatibles de trixie. `+really2.9.14` importa: comparar
solamente el prefijo `2.12.7` llevaría a una conclusión incorrecta.
El tracker identifica el
[commit upstream 463bbeeca1805b5c4828f50d0fefc4eebaf620df](https://github.com/GNOME/libxml2/commit/463bbeeca1805b5c4828f50d0fefc4eebaf620df)
como corrección en 2.11.0; modifica el control de amplificación de entidades en
varios archivos. No se verificó ni aplicó un backport de ese cambio al paquete
Debian instalado.

**Siguiente acción concreta:** conservar el bloqueo y revisar individualmente
un fix oficial compatible de trixie cuando exista. Si se decide evaluar un
backport propio, requiere un alcance nuevo: paquete fuente Debian identificado,
patch upstream trazable, ABI/consumidores, pruebas y artefactos nuevos. No basta
renombrar la versión, copiar bibliotecas de sid ni suprimir el finding.

## Alcance API, worker y PyAV

Los probes fueron sobre la imagen local equivalente, sin red, root filesystem
de solo lectura, UID/GID 10001, sin capacidades ni montajes de datos o secretos.
Se consultaron metadatos de paquetes, dependencias ELF y mappings propios.
El ejemplo XML siguiente se creó sólo en tmpfs del contenedor desechable.

| Ruta / componente | Comprobado | Límite de la conclusión |
| --- | --- | --- |
| API cloud | El código recibe el upload autorizado, guarda GCS/PG y despacha; no ejecuta multimedia. Importar `app.main` no cargó libxml2 en `/proc/self/maps`. | No demuestra ausencia de toda carga futura ni neutraliza el worker que recibe los bytes. |
| Worker: preflight y render/export | `ffprobe` y `ffmpeg` son 7.1.5-0+deb13u1, ambos con `--enable-libxml2` y enlace a `/lib/x86_64-linux-gnu/libxml2.so.2`. | No puede declararse que la biblioteca esté instalada pero inutilizada. |
| PyAV / Whisper | `av 18.1.0` usa su propio `libavformat 62.12.102`; su ELF vendorizado no declara dependencia dinámica libxml2, no exportó `xmlReadMemory` y la importación de PyAV/Whisper no añadió mappings libxml2. El inventario no contiene un ELF vendorizado con nombre libxml. | Esto no descarta código estático/oculto ni prueba cobertura SCA nativa completa. No se traslada la CVE Debian a PyAV ni se declara PyAV no afectado. |

Los metadatos instalados declaran dependencia de libxml2 en `libavformat61`,
`libbluray2`, `libllvm19`, `librsvg2-2` y `shared-mime-info`. Borrar la biblioteca
sin revisar esos consumidores no constituye un fix compatible.

El worker llama `inspect_media` antes de Whisper y también antes de exportar.
`probe_media` usa autodetección de formato: la API comprueba la extensión `.mp4`,
pero el comando no fuerza el demuxer MOV/MP4. La validación de audio/video y
duración ocurre después de que ffprobe analiza el contenedor.

Prueba benigna de alcance: un XML DASH de 227 bytes, sin DTD, entidades, URLs o
medios externos, guardado como `input.mp4`, fue seleccionado por el ffprobe real
como `dash`, score 100, aun con `-protocol_whitelist file,pipe`. Terminó con
código 1 al no contener streams utilizables. **No fue un exploit ni una
reproducción de la UAF**; demuestra que extensión y whitelist de protocolos no
impiden seleccionar el parser XML antes de rechazar el archivo. Un XML mínimo
sin perfil DASH no se seleccionó; no se usó ese resultado como no afectación.
La [fuente oficial de FFmpeg 7.1.5](https://github.com/FFmpeg/FFmpeg/blob/n7.1.5/libavformat/dashdec.c)
confirma que `parse_manifest` llama `xmlReadMemory`.

## Controles, brechas y evidencia requerida

Se conservan autenticación, propiedad y CSRF, despacho fuera de la API, ejecución
sin root, paths de medios verificados, whitelist `file,pipe`, timeout de ffprobe
de 30 segundos, timeout de render de 1800 segundos, stderr acotado y terminación
de FFmpeg al morir su padre. Los controles de proceso tienen regresiones Linux;
el probe actual confirmó usuario y capacidades retiradas de su propio contenedor.
Reducen exposición y duración, pero no corrigen una UAF ni prueban aislamiento
de efectos dentro del proceso. No se afirma que GCP, su red, IAM o Audit Logs
estén desplegados o probados.

Fijar/limitar el demuxer MOV/MP4 antes de analizar bytes y probar archivos
disfrazados sería una defensa adicional a revisar. **No elimina el paquete
vulnerable ni resuelve el gate**. Tampoco se demostró que `file,pipe` controle
todos los loaders internos de libxml2 o que toda entrada admitida sea inocua.

Para resolver el finding se necesita una imagen nueva con paquete corregido
verificable y versión/fuente/hash trazables, inventario/SBOM/SCA completos,
regresión upstream o equivalente de esta CVE y pruebas de todos los consumidores
que efectivamente cargan libxml2. Deben conservarse las regresiones MP4 reales,
Whisper, render/subtítulos, límites de recursos y muerte del padre.

Una declaración de no afectación requeriría demostrar, para este digest y cada
ruta, que el código vulnerable no está presente o no puede recibir la entrada
necesaria: dependencias dinámicas y estáticas, símbolos/opciones de compilación,
selección de demuxers antes del parseo y casos adversos representativos.
Importar módulos, un archivo que falla o un E2E funcional verde no alcanzan.

Residual individual propuesto `INT-RUNTIME-CVE-2026-6653`: componente y digest
anteriores, posible UAF/DoS al procesar entrada XML, parser alcanzable en worker,
explotabilidad específica no comprobada, fix trixie no verificado. Responsable
propuesto: AldemaroCruz; revisar como máximo el 2026-11-27 o ante un fix/cambio.
Permanece **bloqueante y sin aceptación**, igual que los demás HIGH y SAST
pendientes, que este documento no reclasifica.

## VM foundation: preflight separado, sin instalación ni scanner

Consulta puntual de 2026-11-14 UTC. Se leyó únicamente el startup autorizado
`infra/gcp/int-base/postgres-install.sh`: configura `trixie`, `trixie-updates` y
`trixie-security` desde `deb.debian.org`, con `Signed-By` al keyring Debian y
repositorios inseguros deshabilitados. No usa un snapshot de APT.

Los pins `postgresql-17=17.12-0+deb13u1` y
`postgresql-client-17=17.12-0+deb13u1` **siguen disponibles**. Las páginas
oficiales del [servidor](https://packages.debian.org/trixie/postgresql-17) y del
[cliente](https://packages.debian.org/trixie/postgresql-client-17) publican esa
versión en seguridad; el
[tracker de PostgreSQL 17](https://security-tracker.debian.org/tracker/source-package/postgresql-17)
distingue principal 17.11 de seguridad 17.12. Consultas HTTP HEAD al repositorio
oficial devolvieron 200 para ambos `.deb` amd64 exactos y para
`debian-security/dists/trixie-security/InRelease`; no se descargaron ni instalaron
los paquetes. Esto confirma disponibilidad actual, no reproducibilidad futura
ni validación de firmas realizada sobre una VM.

El paquete servidor declara dependencia directa `libxml2 >= 2.7.4`, además de
`libllvm19` y `libxslt1.1`. La versión de libxml2 que hoy publica trixie sigue
marcada vulnerable por la fuente Debian citada arriba. Se propone por ello el
residual **`F-VM-XML`**, riesgo esperado y decisión específica pendiente de preflight.
No existe inventario instalado ni SCA de esa VM: no se le atribuye la versión
efectivamente instalada, un conteo CRITICAL/HIGH del runtime o PostgreSQL de CI,
ni explotabilidad probada. PostgreSQL 17 ofrece
[funciones XML condicionadas a libxml](https://www.postgresql.org/docs/17/functions-xml.html);
el uso y la alcanzabilidad exactos de su futuro binario requieren evidencia propia.

El startup escribe `create_main_cluster = false`, enmascara los servicios antes
y después de instalar y reserva inicialización del disco, TLS, roles, secretos,
arranque y restore para otro procedimiento. Son controles previstos en código,
no observaciones de una VM operativa. Un servicio aún sin inicializar ni escuchar
no equivale a la aplicación multimedia activa; tampoco elimina una dependencia
vulnerable del conjunto instalado. Esta VM no ejecuta los parsers de uploads del
worker multimedia.

Mínimo pendiente antes de decidir foundation: volver a verificar el pin y la
resolución contra metadatos APT firmados y la imagen base exacta, conservando
versiones/hashes de dependencias. El propietario puede decidir sobre **fundación
únicamente**, con este residual individual visible y PostgreSQL masked,
sin cluster ni SQL; esa decisión todavía no existe en esta revisión.
Bootstrap, carga de secretos y puesta en servicio deben seguir prohibidos hasta
contar con inventario/SCA propios de la VM, verificación TLS y revisión específica.
Esto no constituye una aceptación general de CRITICAL/HIGH ni acredita una VM
operativa.

Si resolver `F-VM-XML` exige cambiar pins, repositorio, startup o HCL, debe
prepararse y revisarse un plan nuevo. Esta revisión **no modifica el plan aa68 ni
sus entradas**. Responsable propuesto: AldemaroCruz, por confirmar; revisión
máxima 2026-11-27, sin aceptación. Siempre prevalece el TTL menor del plan: esta
fecha no extiende su vigencia ni permite aplicar un plan vencido.
