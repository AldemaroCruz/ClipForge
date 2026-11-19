# DB-01: seguridad pendiente

La compatibilidad funcional de PostgreSQL 17 ya estÃƒÂ¡ aceptada (63 pruebas,
14 controles y browsers AUTH 7/recuperaciÃƒÂ³n 8). Esa evidencia se conserva;
no equivale a aceptar los hallazgos del guest ni a autorizar su bootstrap.

Estado: `individual_review_completed_security_blocked_no_compatible_fix`.

El scan anterior permanece intacto. La observaciÃƒÂ³n real del run `44424226652`
(SHA-256 `748af07defac48b57236a204701988d849c51372390a36e5cf7c4ecdcc35f5b1`)
aportÃƒÂ³ los siete campos de dpkg para los 368 paquetes: todos
`install ok installed`, con abreviatura literal `ii `.

| Evidencia | CRITICAL | HIGH | MEDIUM | LOW | UNKNOWN | Filas / CVE ÃƒÂºnicas |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Anterior, fuentes no observadas | 1 | 25 | 52 | 76 | 18 | 172 / 172 |
| Actual, fuentes observadas | 7 | 208 | 386 | 379 | 53 | 1033 / 372 |

Los nombres/versiones/arquitecturas de los 368 binarios coinciden exactamente
entre ambas capturas. Se observaron 259 alias de fuente y 42 diferencias de
versiÃƒÂ³n fuente/binario. Trivy 0.76.2 y la DB `d06c4389Ã¢â‚¬Â¦60175` fueron los mismos;
el scan se ejecutÃƒÂ³ sin red con DB montada en solo lectura y su hash posterior
sin cambios. El aumento corresponde a cobertura corregida de fuentes:
200 CVE adicionales; ninguna detecciÃƒÂ³n anterior desapareciÃƒÂ³.

La ejecuciÃƒÂ³n nativa terminÃƒÂ³ con salida 0; **la seguridad continÃƒÂºa bloqueada**.
Las 215 filas CRITICAL/HIGH representan 69 CVE ÃƒÂºnicas y estÃƒÂ¡n conservadas
ÃƒÂ­ntegramente para revisiÃƒÂ³n individual, con sus binarios, fuentes y versiones.
El JSON nativo tiene SHA-256
`91f95617e72f0b378af41296c82738cb89ce5024c0ae8b2a7b2f119084888d25`;
el resumen, `7b50980aac2754466e41c535bc039da0024b9e9ef41aa31bc0a4da53843136bd`.
No hay excepciones ni aceptaciones nuevas. El incremento anterior se detuvo
por instrucciÃƒÂ³n del coordinador tras la limitaciÃƒÂ³n automÃƒÂ¡tica comunicada.
La revisiÃƒÂ³n individual y el laboratorio ordinario descritos abajo corresponden
a una autorizaciÃƒÂ³n posterior distinta; no repiten el ensayo rechazado.

| CVE-2026-6653 | Evidencia y decisiÃƒÂ³n |
| --- | --- |
| Scanner | CRITICAL, fuente NVD; libxml2 figura afectado y sin versiÃƒÂ³n corregida de trixie. Se conserva esa severidad. |
| Proveedor | Debian mantiene trixie vulnerable y anota `no-dsa`/incidencia menor. Es contexto del proveedor, sin aceptaciÃƒÂ³n ni excepciÃƒÂ³n. |
| ExposiciÃƒÂ³n propuesta | PostgreSQL permanece sin inicializaciÃƒÂ³n autorizada. Red privada, TLS y roles DML limitan acceso, pero no demuestran que libxml2 resulte inalcanzable cuando se habilite SQL. |
| CorrecciÃƒÂ³n disponible | No hay versiÃƒÂ³n corregida de trixie identificada en el tracker. No se propone sustituirla por binarios de sid u otra distribuciÃƒÂ³n. |
| Candidato local | El cambio upstream exacto falla en 10 hunks. Una adaptaciÃƒÂ³n de fuentes para la misma base 2.9.14 sÃƒÂ­ se aplica a trixie con sus 40 parches. No existe todavÃƒÂ­a un paquete compatible validado. |

El [tracker de Debian](https://security-tracker.debian.org/tracker/CVE-2026-6653)
vincula la correcciÃƒÂ³n al commit upstream
`463bbeeca1805b5c4828f50d0fefc4eebaf620df`. Su
[diff oficial](https://github.com/GNOME/libxml2/commit/463bbeeca1805b5c4828f50d0fefc4eebaf620df.patch)
modifica siete archivos, incluidas estructuras pÃƒÂºblicas. El ensayo local
verificÃƒÂ³ la cadena InRelease Ã¢â€ â€™ Sources Ã¢â€ â€™ archivos de libxml2; ejecutÃƒÂ³ GNU patch
2.8-2 de Debian con `--fuzz=0` en un contenedor Debian 13 sin red y con el
ÃƒÂ¡rbol de trabajo en tmpfs Linux. Los 40 parches Debian pasaron; el diff upstream
saliÃƒÂ³ 1, sin timeout, con 10 hunks rechazados. No se compilÃƒÂ³ un paquete ni se
probÃƒÂ³ ABI o resoluciÃƒÂ³n de la CVE. Los intentos previos con problemas de bind
Windows/noexec se conservan por separado, sin presentarlos como este resultado.

El ensayo 04 aplicÃƒÂ³ tambiÃƒÂ©n los 40 parches Debian y despuÃƒÂ©s la adaptaciÃƒÂ³n
de fuentes publicada por Canonical (`6c2b8a7b6fa470efcb1854e5c73bd7e1ae1663d8b111e27ce9232bbc1fe44f54`):
salida 0, cero hunks rechazados, sin fuzz ni timeout. El
[aviso oficial](https://ubuntu.com/security/notices/USN-8456-1) identifica
esa correcciÃƒÂ³n para la misma base 2.9.14. Se obtuvo exclusivamente el diff
del archivo de fuentes oficial, comprobando su SHA contra el DSC recibido
por HTTPS; la firma de ese DSC no se verificÃƒÂ³. No se descargaron ni
instalaron binarios de otra distribuciÃƒÂ³n.

La preparaciÃƒÂ³n de herramientas terminÃƒÂ³ en una imagen desechable basada
en Debian 13; se verificÃƒÂ³ la firma del ÃƒÂ­ndice Debian de los headers usados.
El primer build fallÃƒÂ³ por versiones de headers incompatibles con las librerÃƒÂ­as
de trixie-security presentes; el segundo usÃƒÂ³ las versiones correspondientes
y terminÃƒÂ³ correctamente. **En aquel incremento se detuvieron los ensayos antes
de compilar libxml2 o ejecutar el PoC.** No se probÃƒÂ³ entonces ABI, regresiÃƒÂ³n de
la CVE ni paquete Debian.
Se conservaron fuentes, resultados y la imagen de herramientas; la consulta
de sus labels propios mostrÃƒÂ³ cero contenedores pendientes.
El coordinador comunicÃƒÂ³ que la revisiÃƒÂ³n automÃƒÂ¡tica externa del contenido
del agente (`outer agent content flag`) rechazÃƒÂ³ continuar los ensayos de
vulnerabilidad/PoC. Se acatÃƒÂ³ el bloqueo; no fue un error de GCP o GitHub.

La propuesta revisable estÃƒÂ¡ en
[db01-remediation-proposal.json](../config/db01-remediation-proposal.json).
El siguiente paso requiere un backport revisado para esas fuentes, regresiÃƒÂ³n
de la CVE con instrumentaciÃƒÂ³n de memoria, suite de libxml2 y comprobaciÃƒÂ³n de
ABI/funciones XML de PostgreSQL 17. No se asigna una versiÃƒÂ³n de paquete ficticia
ni se instala nada en la VM.

La exposiciÃƒÂ³n se revisarÃƒÂ¡ por hallazgo. Las
[operaciones XML de PostgreSQL](https://www.postgresql.org/docs/17/datatype-xml.html)
pueden invocar libxml2; la ausencia de un parser de uploads no demuestra
ausencia de exposiciÃƒÂ³n SQL. Por otra parte,
[CVE-2026-74860](https://security-tracker.debian.org/tracker/CVE-2026-74860)
afecta especÃƒÂ­ficamente bindings Python SAX: necesita clasificaciÃƒÂ³n individual
con evidencia del binario/componente presente. No se suprime por inferencia.

El conversor de SBOM v2 exige el recibo GUEST completo, su hash exacto, la
prueba del disco y concordancia de los siete campos observados de dpkg con
la captura base. Exporta propiedades de fuente compatibles con Trivy, pero
se identifica como conversor de terceros. El resultado nativo debe conservar
cada PURL binario y su fuente/versiÃƒÂ³n exacta. Se mantienen los estados completos
de dpkg; errores o instalaciones parciales bloquean la preparaciÃƒÂ³n. Esto sigue
siendo SCA de metadatos de paquetes, sin cobertura total de ficheros, paquetes
de lenguajes o alcanzabilidad. No hay nuevas aceptaciones de riesgo, filtros,
`ignore-unfixed`, cambios IAM ni permiso de despliegue.

Los operadores nuevos conservan sus hallazgos SAST para revisiÃƒÂ³n individual;
la justificaciÃƒÂ³n de permisos de directorio o de un subprocess acotado no
constituye una aceptaciÃƒÂ³n. F-SAST-EXEC histÃƒÂ³rico no cubre nuevos llamadores
de preparaciÃƒÂ³n, transporte o experimentos locales.

El informe nativo de operadores/launcher/cliente conserva **7 LOW y 1 MEDIUM**
(SHA-256 `69a135df1d50d7fd2f3bf37a66c9cac4e7a1bad4230d6791e50603898abba323`):

| Regla | Resultado actual y revisiÃƒÂ³n pendiente |
| --- | --- |
| B105, 5 LOW | Nombres de variables, rutas/IDs de secretos y literal de SCRAM. Son identificadores/configuraciÃƒÂ³n; cada alerta sigue visible y sin excepciÃƒÂ³n. |
| B404/B603, 2 LOW | Import y ejecuciÃƒÂ³n de subprocess del operador nuevo. Requieren revisiÃƒÂ³n propia; la aceptaciÃƒÂ³n histÃƒÂ³rica no se transfiere. |
| B103, 1 MEDIUM | Directorio raÃƒÂ­z `0710`: acceso de recorrido para el grupo postgres. El journal privado continÃƒÂºa `0700` y los ficheros secretos `0600`; esta finalidad no acepta el finding automÃƒÂ¡ticamente. |

Ese informe no escanea el nuevo helper del ensayo de fuentes ni reemplaza
la evidencia separada del transporte de la captura GUEST.

## RevisiÃƒÂ³n individual de los 20 grupos

El JSON de [remediaciÃƒÂ³n](../config/db01-remediation-proposal.json) conserva
69 registros individuales y sus 215 relaciones exactas con binarios, fuente,
versiÃƒÂ³n, arquitectura y severidad original. Cada registro incluye componente,
condiciÃƒÂ³n, evidencia observada, lÃƒÂ­mites, estado del proveedor, correcciÃƒÂ³n
pendiente y enlace primario. Ninguna clasificaciÃƒÂ³n elimina una fila del scanner.

La consulta oficial de Debian terminÃƒÂ³ el **19 de noviembre de 2026 a las
02:38:37 UTC**. Su JSON pÃƒÂºblico tiene SHA-256
`29227c321eb85d316a354d143f2c224fb3517c933d733993decd605780624725`.
Los 69 registros requeridos estÃƒÂ¡n presentes y siguen abiertos para trixie:
no se verificÃƒÂ³ una versiÃƒÂ³n corregida de esa distribuciÃƒÂ³n. Las anotaciones
`no-dsa`, `Minor issue`, `ignored` o `postponed` son decisiones del proveedor,
no aceptaciones del propietario ni excepciones de ClipForge. Las versiones
corregidas de sid/forky se registran sÃƒÂ³lo como referencias de fuentes; no se
propone instalarlas ni mezclar sus binarios.

| Fuente observada / proveedor | CRITICAL / HIGH | Componente y exposiciÃƒÂ³n demostrada; residual |
| --- | ---: | --- |
| [acl](https://security-tracker.debian.org/tracker/source-package/acl) | 0 / 1 | libacl1 instalado; no se observaron operaciones ACL sobre rutas de un tercero. Verificar quÃƒÂ© consumidores pasan rutas modificables por otros usuarios a libacl; no inferir ausencia por no instalar el CLI acl. |
| [curl](https://security-tracker.debian.org/tracker/source-package/curl) | 0 / 4 | curl y libcurl instalados; opciones SCP/SFTP y autenticaciÃƒÂ³n Negotiate usadas en la VM no fueron inventariadas. Revisar los consumidores y opciones concretas; los usos TLS normales no prueban estas condiciones. |
| [dracut](https://security-tracker.debian.org/tracker/source-package/dracut) | 0 / 3 | SÃƒÂ³lo dracut-install instalado; paquetes dracut y dracut-core no observados. La lista oficial de dracut-install no incluye mÃƒÂ³dulos de red initramfs. Inventario de paquetes no atesta el contenido efectivo del initramfs; falta ese vÃƒÂ­nculo antes de cerrar alcance. |
| [expat](https://security-tracker.debian.org/tracker/source-package/expat) | 0 / 4 | libexpat1 instalado; no hay traza de llamadas o XML de terceros procesado en la VM. Identificar consumidores y lÃƒÂ­mites de XML antes de habilitar entradas no confiables. |
| [grub2](https://security-tracker.debian.org/tracker/source-package/grub2) | 0 / 5 | Binarios GRUB instalados; no se capturÃƒÂ³ uso del comando gettext tras descargar un mÃƒÂ³dulo. Verificar selecciÃƒÂ³n efectiva de arranque y acceso local; Secure Boot no demuestra por sÃƒÂ­ solo ausencia de esta ruta. |
| [krb5](https://security-tracker.debian.org/tracker/source-package/krb5) | 0 / 70 | Bibliotecas y locales krb5 instalados; krb5-kdc, krb5-admin-server y bibliotecas GSS-RPC/administraciÃƒÂ³n dedicadas no observados. Separar incidencias de KDC/kadmind de bibliotecas cliente; las incidencias sin descripciÃƒÂ³n necesitan el aviso MIT. No se atesta todo el filesystem. |
| [libpcap](https://security-tracker.debian.org/tracker/source-package/libpcap) | 0 / 2 | libpcap instalado; no se observÃƒÂ³ un consumidor que ejecute filtros BPF controlados por un tercero. Verificar consumidores y origen de filtros; la instalaciÃƒÂ³n no prueba uso del intÃƒÂ©rprete. |
| [libxml2](https://security-tracker.debian.org/tracker/source-package/libxml2) | 1 / 7 | libxml2 instalado; PostgreSQL permanece enmascarado, inactivo y sin clÃƒÂºster. El SQL XML futuro puede invocar libxml2. No habilitar SQL hasta revisar el componente especÃƒÂ­fico y contar con correcciÃƒÂ³n compatible. Los bindings Python se clasifican por separado. |
| [lmdb](https://security-tracker.debian.org/tracker/source-package/lmdb) | 3 / 2 | liblmdb0 instalado; no se observÃƒÂ³ uso de base LMDB ni lectura de archivos MDB de terceros. Verificar consumidores y procedencia de archivos; ausencia de uso observado no equivale a archivo seguro ni a eliminaciÃƒÂ³n del finding. |
| [ncurses](https://security-tracker.debian.org/tracker/source-package/ncurses) | 0 / 4 | ncurses-bin e interfaces de terminal instalados; no se observÃƒÂ³ procesamiento de datos de terminal de terceros por infocmp. SÃƒÂ³lo infocmp es el componente descrito; las filas de las bibliotecas y datos se conservan como atribuciÃƒÂ³n de fuente. |
| [openssh](https://security-tracker.debian.org/tracker/source-package/openssh) | 3 / 15 | Cliente, servidor y SFTP instalados. Acceso entrante estricto fue observado; configuraciÃƒÂ³n GSSAPI/forwarding efectiva y usos salientes de ssh no fueron capturados. Separar cliente y servidor por CVE. El cliente GHA no es el paquete cliente de la VM; no extrapolar versiones ni exposiciÃƒÂ³n. |
| [perl](https://security-tracker.debian.org/tracker/source-package/perl) | 0 / 4 | Perl y mÃƒÂ³dulos instalados; no se observaron archivos tar de terceros procesados por Archive::Tar. La correcciÃƒÂ³n del proveedor estÃƒÂ¡ pospuesta por regresiones upstream; no actualizar ÃƒÂºnicamente ese mÃƒÂ³dulo sin compatibilidad demostrada. |
| [python-urllib3](https://security-tracker.debian.org/tracker/source-package/python-urllib3) | 0 / 3 | python3-urllib3 del sistema instalado; no se observÃƒÂ³ configuraciÃƒÂ³n de proxy ni trÃƒÂ¡fico HTTP de sus consumidores en la VM. Clasificar streaming/proxy por consumidor; no atribuirle la versiÃƒÂ³n Python/urllib3 de las imÃƒÂ¡genes CI o runtime. |
| [python3.13](https://security-tracker.debian.org/tracker/source-package/python3.13) | 0 / 20 | Python 3.13 del sistema instalado y usado por la captura GUEST; no hay cobertura de todas sus aplicaciones. Las rutas HTML, XML, SNI y extracciÃƒÂ³n son condiciones separadas. Los controles ejecutados en GHA Python 3.12 no prueban la VM 3.13. |
| [rsyslog](https://security-tracker.debian.org/tracker/source-package/rsyslog) | 0 / 2 | rsyslog instalado; rsyslog-clickhouse no observado. No se leyÃƒÂ³ configuraciÃƒÂ³n efectiva de dynaFile ni plugins. Separar plugin ausente del inventario y plantilla omfile. Evitar publicar configuraciones con datos privados. |
| [sqlite3](https://security-tracker.debian.org/tracker/source-package/sqlite3) | 0 / 3 | libsqlite3-0 instalado; no se observaron consumidores, opciones FTS5/session ni archivos SQLite de terceros. Verificar opciones compiladas y consumidores sin abrir datos del propietario; PostgreSQL no usa SQLite como backend de la aplicaciÃƒÂ³n. |
| [sudo](https://security-tracker.debian.org/tracker/source-package/sudo) | 0 / 1 | sudo fue usado para el acceso GUEST. No se capturaron reglas sudoers NOTBEFORE/NOTAFTER ni su formato de zona horaria. Revisar metadatos de las reglas relevantes. Una ventana temporal IAM no es una regla sudoers ni prueba esta condiciÃƒÂ³n. |
| [systemd](https://security-tracker.debian.org/tracker/source-package/systemd) | 0 / 12 | systemd y bibliotecas instalados; paquete systemd-homed no observado. El componente vulnerable es homed, no toda funciÃƒÂ³n de systemd. Falta attestation de binarios/usuarios gestionados; no suprimir las 12 filas. |
| [util-linux](https://security-tracker.debian.org/tracker/source-package/util-linux) | 0 / 44 | Utilidades instaladas; kernel observado 6.12.117+deb13-cloud-amd64. El bootstrap propuesto no usa nsenter ni hooks X-mount. Revisar permisos/options de fstab y uso privilegiado. La condiciÃƒÂ³n kernel >=6.15 de CVE-2026-78409 no se cumple en la captura, pero un cambio de kernel exige revisiÃƒÂ³n. |
| [wget](https://security-tracker.debian.org/tracker/source-package/wget) | 0 / 2 | wget instalado; no se observÃƒÂ³ descarga/conversiÃƒÂ³n de archivos o HTML no confiables por ese programa en la VM. Verificar consumidores; existencia de HTTP en otro programa no demuestra esta ruta. |

Hay diferencias materiales de componente. CVE-2026-60002 afecta **al cliente
ssh**; su atribuciÃƒÂ³n tambiÃƒÂ©n a paquetes servidor/SFTP por compartir fuente no
demuestra un defecto del endpoint entrante. El cliente de la VM sÃƒÂ­ estÃƒÂ¡
instalado, pero no se observÃƒÂ³ uso saliente de ÃƒÂ©l. Para dracut, sÃƒÂ³lo se observÃƒÂ³
`dracut-install`: su [lista oficial de archivos](https://packages.debian.org/trixie/amd64/dracut-install/filelist)
no contiene los mÃƒÂ³dulos de red initramfs descritos. Esto no atesta un initramfs
copiado manualmente. `systemd-homed`, `rsyslog-clickhouse`, `python3-libxml2`,
KDC/kadmind y sus paquetes dedicados no aparecen en el inventario; no se
transforma esa ausencia de paquetes en una prueba completa del filesystem.

El [plugin omclickhouse](https://packages.debian.org/trixie/amd64/rsyslog-clickhouse/filelist)
se distribuye separado; la otra incidencia rsyslog exige revisar `dynaFile`.
CVE-2026-78409 describe una ruta de kernel >=6.15; la captura observa
`6.12.117+deb13-cloud-amd64`. Esa condiciÃƒÂ³n concreta no se cumple en la
captura, pero se conserva la fila y debe revisarse ante cambios de kernel.
No se declara cubierto el kernel por este SCA de paquetes. La captura conserva
`linux-image-6.12.117+deb13-cloud-amd64` y `linux-image-cloud-amd64`,
binarios `6.12.117-1`, fuente **linux-signed-amd64 `6.12.117+1`**, amd64,
con estado `ii `. No se cambia ese nombre a `linux`: falta revisar la
relaciÃ³n signed/build con el cÃ³digo fuente kernel y sus advisories. No se
afirman cero CVE, aprobaciÃ³n del kernel ni integridad de firma del binario.

Las fichas Debian de krb5 CVE-2026-107364, CVE-2026-118380 y CVE-2026-71200
no aportaron descripciÃƒÂ³n de componente en el conjunto consultado; enlazan un
aviso MIT que no pudo leerse con la herramienta web. Sus estados vulnerables
y sus relaciones binarias se conservan: el detalle y la decisiÃƒÂ³n residual
siguen pendientes, sin inventar alcance ni asumir que todos sean sÃƒÂ³lo KDC.

## CompilaciÃƒÂ³n y empaquetado ordinarios de libxml2

La tarea posterior permitiÃƒÂ³ procedencia, compilaciÃƒÂ³n, empaquetado, ABI
seleccionada y XML funcional ordinario. El helper nuevo
[db01_libxml_packaging.py](../scripts/db01_libxml_packaging.py) es independiente
del ensayo anterior. No ejecuta la suite upstream, regresiones de CVE,
ASAN, PoC ni entradas de explotaciÃƒÂ³n. Se conserva la detenciÃƒÂ³n histÃƒÂ³rica.

La imagen de herramientas Debian 13
`sha256:90521ae85440179e9893d14a7a70649cffedc29e032c434bf3196eccc55a631e`
se ejecutÃƒÂ³ sin red, sin capacidades, con UID/GID 10001, raÃƒÂ­z de sÃƒÂ³lo lectura
y ÃƒÂ¡rbol nuevo en tmpfs privado. Se volvieron a comprobar los hashes de los
dos archivos Debian, GNU patch y la adaptaciÃƒÂ³n `6c2b8a7bÃ¢â‚¬Â¦44f54`; los 40
parches Debian y despuÃƒÂ©s esa adaptaciÃƒÂ³n se aplicaron con cero fuzz.

Se conservaron dos fallos de preparaciÃƒÂ³n: la primera lectura usÃƒÂ³ el enlace
estÃƒÂ¡ndar `/etc/os-release` y se corrigiÃƒÂ³ al destino fijo `/usr/lib/os-release`;
el siguiente make intentÃƒÂ³ regenerar autotools sin `aclocal`. El tercer
intento usÃƒÂ³ los archivos generados del tarball con `--disable-maintainer-mode`.
No se descargaron nuevas herramientas ni se ejecutaron pruebas omitidas por
ese cambio. La compilaciÃƒÂ³n normal, el staging privado y la construcciÃƒÂ³n del
paquete de laboratorio terminaron con salida 0.

| ComprobaciÃƒÂ³n ordinaria | Resultado real |
| --- | --- |
| Biblioteca base | Debian trixie `2.12.7+dfsg+really2.9.14-2.1+deb13u3`. |
| Exportaciones dinÃƒÂ¡micas versionadas | 1786 en base y candidata, sin sÃƒÂ­mbolos retirados ni aÃƒÂ±adidos. |
| SONAME | `libxml2.so.2` conservado. |
| Layout pÃƒÂºblico seleccionado | **Falla**: `sizeof(xmlParserInput)` 104 Ã¢â€ â€™ 120. `xmlParserCtxt`, `xmlNode`, `xmlDoc` y tres offsets seleccionados coinciden. No es una comprobaciÃƒÂ³n exhaustiva de ABI. |
| XML vÃƒÂ¡lido propio | Parseo, XPath, reader y writer con roundtrip pasaron; `XML_PARSE_NONET`, sin DTD ni recursos externos. |
| Paquete | `clipforge-db01-libxml-lab`, sÃƒÂ³lo `/opt/clipforge-db01/lib`; sin Provides/Replaces/Conflicts ni scripts de mantenimiento. No instalado. |
| PostgreSQL con la candidata | No ejecutado: el cambio de layout bloquea recomendar este binario como reemplazo. |
| ResoluciÃƒÂ³n de CVE | No demostrada; ningÃƒÂºn resultado ordinario cambia las 8 CVE de libxml2 ni el resto de los 20 grupos. |

El recibo `ordinary-build.json` tiene SHA-256
`f7b0b916f9d1fddb28ceec4b4ee21e27b50d93dd2ed5fc65feee730e41cb638a`.
La biblioteca tiene SHA-256
`2daba68a9f3f00f8371dbe478e4842e22247e660890d094dc31f2fdd73f16a70`;
el `.deb` de laboratorio,
`9afb751f91314d35bdbcea099e4cdf6879141f75bb3bff515dceeb19361cf821`.
Son artefactos de investigaciÃƒÂ³n, no una actualizaciÃƒÂ³n Debian aprobada.

La cadena de ÃƒÂ­ndices Debian firmados del expediente anterior se conserva.
Este helper valida hashes de entradas y no realiza una nueva verificaciÃƒÂ³n
PGP de DSC. La firma del DSC de la adaptaciÃƒÂ³n Canonical sigue sin verificarse.
Tampoco se atestan integridad de binarios instalados, origen de repositorios,
filesystem completo ni seguridad del kernel.

Una bifurcaciÃƒÂ³n mantenida exige asignar responsable, revisar cada advisory y
dependencia, mantener/rebasar los 40 parches Debian, definir polÃƒÂ­tica ABI y
empaquetado firmado, conservar SBOM y regresiones ordinarias de consumidores,
y someter instalaciÃƒÂ³n/rollback a otra decisiÃƒÂ³n concreta. No se ha estimado ni
aceptado ese coste continuo. El laboratorio no crea servicios cloud ni amplÃƒÂ­a
el presupuesto operativo. El cambio de layout, las correcciones aÃƒÂºn no
validadas y las decisiones individuales residuales mantienen el bloqueo.
