# DB-01: estabilización y decisión de activación

La fundación y GUEST-01 permanecen cerrados. Esta entrega prepara controles y
artefactos; **no autoriza ni ejecuta bootstrap, SQL, secretos, grants, publicación
de imágenes o creación de Jobs en INT**. Se reutilizan las pruebas PG17 aceptadas.

## Causa funcional demostrada

El baseline limpio del commit `6c69ddc` reprodujo los 50 errores en 162 pruebas
de cinco módulos. Todos fueron `FileNotFoundError`: contrato de fundación (5),
fixture SAST (3), contrato de recuperación (3), `versions.tf` (7), referencias
históricas 5800b4c (1) y 79ecadb (2), contrato IAP (1) y startup de VM (28).
El selector y la imagen CI omitían esos soportes públicos.

La selección nueva contiene nombres literales y ancestros exactos; no recorre
`config/` o `infra/` buscando archivos. El Dockerfile y su ignore independiente
copian los soportes del contexto verificado. Claves, estados y datos privados
siguen excluidos, incluso si se fuerzan en Git. Discovery, cero omisiones,
checks nativos y gates de seguridad no cambian.

El runner conserva por prueba fallida su ID, tipo de excepción y frames de
traceback con ruta pública, función y línea. Para un archivo ausente conserva
su nombre sólo si pertenece al conjunto permitido. No conserva mensajes
arbitrarios, valores de locales, líneas de código, stdout/stderr de pruebas ni
parámetros de subtests. Los informes históricos no se completan retroactivamente.

La reproducción inicial postfix usó un snapshot local del working tree e incluyó
archivos no versionados; se conserva con ese alcance. La certificación del cambio
corresponde a la validación posterior de los blobs exactos del índice y al run
integrado del SHA final, cuyos recibos se entregan fuera del commit.

## Señales y límites SQL

`int_bootstrap_vm.native` mata/recolecta únicamente el grupo de procesos propio,
conserva la operación, salida realmente observada y diagnóstico acotado, y lo
entrega al journal antes de propagar la interrupción. Si no pudo observar salida,
no inventa un código. La regresión Linux incluye una señal real al proceso padre.

El cliente pasa un engine explícito a las dos llamadas de `upgrade(engine)`:
`connect_timeout=5`, `statement_timeout=15000`, `lock_timeout=3000`, schema public,
`NullPool` y parámetros ocultos. Se dispone incluso tras fallo. Los bloqueos
ocupados de AUTH y cloud se probaron en PostgreSQL 17.12 desechable con TLS:
ambos devolvieron `55P03` cerca de tres segundos. Un fallo cloud conservó las
revisiones AUTH ya confirmadas; al liberar únicamente el lock propio, la
migración terminó y una segunda llamada informó `current`.

## Contención exacta propuesta

La política v2 está desautorizada. Su inclusión futura requiere aprobar dos
efectos: crear exclusivamente `/var/lib/clipforge-postgres/db01/containment-intent.json`
en modo 0600 con fsync de archivo/directorio, y enviar una sola vez:

```text
/usr/bin/systemctl stop postgresql@17-main.service
```

Se exige un recibo con fallo parcial verificado y terminado del mismo bootstrap
y arranque, journal privado con hash exacto, UUID/montaje propios, configuración
conservada y PID/postmaster.pid/PGDATA/cwd/start ticks coincidentes. Se fija el
template autenticado de `postgresql-common 278` por SHA-256; se rechazan drop-ins,
recarga pendiente o un `ExecStop` efectivo distinto. Un bootstrap exitoso o aún
en ejecución no habilita STOP.

El launcher sólo considera esta acción antes de su limpieza y bajo autorización
expresa. Reutiliza el mismo túnel, host pin, usuario y clave. Exige al menos 280 s
restantes de clave y token para reservar 100 s de transporte y 180 s de limpieza;
el helper dispone de 90 s. Si falta recibo verificable o margen, no intenta STOP.
El resultado original sigue siendo fallo aunque la contención termine bien.

La intención se consume incluso tras un resultado desconocido: no se reemplaza,
borra ni reutiliza. No se reinicializa, desmonta, restaura configuración, elimina
datos, enmascara, habilita o reinicia nada. Se preservan el journal original,
disco, UUID y configuración; el apagado normal puede escribir el checkpoint de
PostgreSQL. Un timeout del cliente no cancela el job de systemd: el template
revisado tiene `TimeoutStopSec=1h`. El resultado queda indeterminado hasta una
lectura posterior; no se envía otro STOP. Ningún reinicio de VM o servicio está
incluido. Si venció la autoridad, se conserva evidencia y se requiere otra
decisión específica, sin prolongar ventanas.

## Seguridad: resultados y límites

La matriz de [remediación](../config/db01-remediation-proposal.json) mantiene las
215 filas originales, 69 identificadores y 20 fuentes, con severidad del scanner
y evaluación del proveedor separadas. No aplica aceptaciones ni supresiones.
Las tres CVE LMDB requieren evaluar el origen de archivos MDB; el inventario no
prueba todos sus consumidores. La CVE OpenSSH 60002 corresponde al cliente ssh,
no al endpoint sshd de entrada; no se elimina ninguna de sus tres filas. Libxml2
sigue requiriendo una solución o decisión individual antes de activar SQL XML.
Tres descripciones krb5 no están disponibles en las fuentes consultadas; se
declara esa falta. El kernel firmado conserva sus nombres/versiones observados;
la cobertura de `linux-signed-amd64` no demuestra cobertura del código kernel.

El laboratorio libxml2 compiló fuentes custodiadas y pasó XML ordinario. La
comprobación ABI seleccionada falló: `xmlParserInput` cambia de 104 a 120 bytes,
aunque SONAME y exports coinciden. El `.deb` de laboratorio usa un prefijo privado
y no reemplaza el paquete del sistema. No se recomienda su instalación ni se
declara corregida la CVE. El ensayo de vulnerabilidad rechazado permanece
conservado y no se repitió. Adoptar un fork requeriría procedencia verificable,
mantenimiento de todos los parches Debian, ABI/consumidores y nuevas versiones;
no sólo mantener este parche. Véase [seguridad](DB-01-security.md).

## Cliente, inputs y escrituras pendientes

La propuesta del [cliente](../config/db01-migration-client-proposal.json) fija
un manifiesto OCI local. La actualización firmada de `zlib1g` a Debian 13 u1
retiró exactamente un HIGH y un MEDIUM en su propio scan; el resto de componentes
quedó idéntico. Las pruebas de compresión e imports son ordinarias. Persisten
47 HIGH del cliente sin aceptación. No se trasladan resultados del cliente a la
VM, PostgreSQL de CI, navegador o aplicación completa.

Las capas GZIP del candidato de publicación conservan el mismo config digest y
los nueve `diff_ids` del filesystem analizado. La copia local con la herramienta
oficial fijada y `--preserve-digests` pasó. No se ha autenticado ni publicado
nada en Artifact Registry; esa compatibilidad se comprobará durante la operación
específica, deteniéndose si no conserva el digest. Los 28 objetos compartidos
inventariados, incluidas bibliotecas vendorizadas de psycopg, no quedan cubiertos
completamente por el análisis de paquetes OS.

Las decisiones se reúnen en [activation-preparation](../config/db01-activation-preparation.json):

| Decisión pendiente | Alcance exacto |
| --- | --- |
| Custodia y emisión | Elegir emisor/renovación TLS y custodio; mínimo siete días restantes, SAN IP 10.80.1.2, claves correspondientes. No enviar secretos en chat. |
| Cinco inputs GitHub int | App/migrator passwords, CA pública, certificado y clave del servidor. La clave privada de CA queda fuera. Mantener mismos valores durante bootstrap/publicación. |
| Publicación OCI | Un artefacto local ya construido, con digest verificado; no rebuild, despliegue o IAM implícitos. |
| Bootstrap y contención | Una inicialización del disco exacto; política de fallo v2 sólo si se autoriza expresamente. Las banderas actuales siguen false. |
| Tres versiones Secret Manager | App password, migrator password y CA; una escritura por contenedor, recibos numéricos reales, sin latest ni reintento ante resultado desconocido. |
| Dos Jobs Direct VPC | Crear y ejecutar migración y aceptación con identidades separadas, imagen por digest y versiones numéricas; source 10.80.0.0/26, maxRetries 0. |

No se inventan los números de versiones que producirían futuras escrituras.
`job_spec` y `job_run_request` ya construyen las definiciones y la autoridad
cerrada cuando existan sus recibos. No se usa superusuario para migrar o aceptar,
ni se amplía HBA/firewall. Publicar imagen, inputs, secretos y Jobs requieren
sus autorizaciones e `int`; no están incluidos en esta estabilización.

La decisión actual es **no activar**. La corrección funcional de CI no modifica
sus gates SAST/SCA, ni las aceptaciones antiguas de fundación. Además de los
hallazgos de VM y cliente, hace falta una decisión explícita sobre inputs,
escrituras y alcance. No se amplía la vigencia de riesgos anteriores. Admin,
backup/restore y release siguen separados; DEV y la instalación operativa se
preservan.
