# DB-01: seguridad pendiente

La compatibilidad funcional de PostgreSQL 17 ya está aceptada (63 pruebas,
14 controles y browsers AUTH 7/recuperación 8). Esa evidencia se conserva;
no equivale a aceptar los hallazgos del guest ni a autorizar su bootstrap.

Estado: `completed_scan_security_blocked_pending_individual_review`.

El scan anterior permanece intacto. La observación real del run `44424226652`
(SHA-256 `748af07defac48b57236a204701988d849c51372390a36e5cf7c4ecdcc35f5b1`)
aportó los siete campos de dpkg para los 368 paquetes: todos
`install ok installed`, con abreviatura literal `ii `.

| Evidencia | CRITICAL | HIGH | MEDIUM | LOW | UNKNOWN | Filas / CVE únicas |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Anterior, fuentes no observadas | 1 | 25 | 52 | 76 | 18 | 172 / 172 |
| Actual, fuentes observadas | 7 | 208 | 386 | 379 | 53 | 1033 / 372 |

Los nombres/versiones/arquitecturas de los 368 binarios coinciden exactamente
entre ambas capturas. Se observaron 259 alias de fuente y 42 diferencias de
versión fuente/binario. Trivy 0.76.2 y la DB `d06c4389…60175` fueron los mismos;
el scan se ejecutó sin red con DB montada en solo lectura y su hash posterior
sin cambios. El aumento corresponde a cobertura corregida de fuentes:
200 CVE adicionales; ninguna detección anterior desapareció.

La ejecución nativa terminó con salida 0; **la seguridad continúa bloqueada**.
Las 215 filas CRITICAL/HIGH representan 69 CVE únicas y están conservadas
íntegramente para revisión individual, con sus binarios, fuentes y versiones.
El JSON nativo tiene SHA-256
`91f95617e72f0b378af41296c82738cb89ce5024c0ae8b2a7b2f119084888d25`;
el resumen, `7b50980aac2754466e41c535bc039da0024b9e9ef41aa31bc0a4da53843136bd`.
No hay excepciones ni aceptaciones nuevas. El análisis adicional se detuvo
por instrucción del coordinador tras la limitación automática comunicada.

| CVE-2026-6653 | Evidencia y decisión |
| --- | --- |
| Scanner | CRITICAL, fuente NVD; libxml2 figura afectado y sin versión corregida de trixie. Se conserva esa severidad. |
| Proveedor | Debian mantiene trixie vulnerable y anota `no-dsa`/incidencia menor. Es contexto del proveedor, sin aceptación ni excepción. |
| Exposición propuesta | PostgreSQL permanece sin inicialización autorizada. Red privada, TLS y roles DML limitan acceso, pero no demuestran que libxml2 resulte inalcanzable cuando se habilite SQL. |
| Corrección disponible | No hay versión corregida de trixie identificada en el tracker. No se propone sustituirla por binarios de sid u otra distribución. |
| Candidato local | El cambio upstream exacto falla en 10 hunks. Una adaptación de fuentes para la misma base 2.9.14 sí se aplica a trixie con sus 40 parches. No existe todavía un paquete compatible validado. |

El [tracker de Debian](https://security-tracker.debian.org/tracker/CVE-2026-6653)
vincula la corrección al commit upstream
`463bbeeca1805b5c4828f50d0fefc4eebaf620df`. Su
[diff oficial](https://github.com/GNOME/libxml2/commit/463bbeeca1805b5c4828f50d0fefc4eebaf620df.patch)
modifica siete archivos, incluidas estructuras públicas. El ensayo local
verificó la cadena InRelease → Sources → archivos de libxml2; ejecutó GNU patch
2.8-2 de Debian con `--fuzz=0` en un contenedor Debian 13 sin red y con el
árbol de trabajo en tmpfs Linux. Los 40 parches Debian pasaron; el diff upstream
salió 1, sin timeout, con 10 hunks rechazados. No se compiló un paquete ni se
probó ABI o resolución de la CVE. Los intentos previos con problemas de bind
Windows/noexec se conservan por separado, sin presentarlos como este resultado.

El ensayo 04 aplicó también los 40 parches Debian y después la adaptación
de fuentes publicada por Canonical (`6c2b8a7b6fa470efcb1854e5c73bd7e1ae1663d8b111e27ce9232bbc1fe44f54`):
salida 0, cero hunks rechazados, sin fuzz ni timeout. El
[aviso oficial](https://ubuntu.com/security/notices/USN-8456-1) identifica
esa corrección para la misma base 2.9.14. Se obtuvo exclusivamente el diff
del archivo de fuentes oficial, comprobando su SHA contra el DSC recibido
por HTTPS; la firma de ese DSC no se verificó. No se descargaron ni
instalaron binarios de otra distribución.

La preparación de herramientas terminó en una imagen desechable basada
en Debian 13; se verificó la firma del índice Debian de los headers usados.
El primer build falló por versiones de headers incompatibles con las librerías
de trixie-security presentes; el segundo usó las versiones correspondientes
y terminó correctamente. **Se detuvieron los ensayos antes de compilar libxml2
o ejecutar el PoC.** No se probó ABI, regresión de la CVE ni paquete Debian.
Se conservaron fuentes, resultados y la imagen de herramientas; la consulta
de sus labels propios mostró cero contenedores pendientes.
El coordinador comunicó que la revisión automática externa del contenido
del agente (`outer agent content flag`) rechazó continuar los ensayos de
vulnerabilidad/PoC. Se acató el bloqueo; no fue un error de GCP o GitHub.

La propuesta revisable está en
[db01-remediation-proposal.json](../config/db01-remediation-proposal.json).
El siguiente paso requiere un backport revisado para esas fuentes, regresión
de la CVE con instrumentación de memoria, suite de libxml2 y comprobación de
ABI/funciones XML de PostgreSQL 17. No se asigna una versión de paquete ficticia
ni se instala nada en la VM.

La exposición se revisará por hallazgo. Las
[operaciones XML de PostgreSQL](https://www.postgresql.org/docs/17/datatype-xml.html)
pueden invocar libxml2; la ausencia de un parser de uploads no demuestra
ausencia de exposición SQL. Por otra parte,
[CVE-2026-74860](https://security-tracker.debian.org/tracker/CVE-2026-74860)
afecta específicamente bindings Python SAX: necesita clasificación individual
con evidencia del binario/componente presente. No se suprime por inferencia.

El conversor de SBOM v2 exige el recibo GUEST completo, su hash exacto, la
prueba del disco y concordancia de los siete campos observados de dpkg con
la captura base. Exporta propiedades de fuente compatibles con Trivy, pero
se identifica como conversor de terceros. El resultado nativo debe conservar
cada PURL binario y su fuente/versión exacta. Se mantienen los estados completos
de dpkg; errores o instalaciones parciales bloquean la preparación. Esto sigue
siendo SCA de metadatos de paquetes, sin cobertura total de ficheros, paquetes
de lenguajes o alcanzabilidad. No hay nuevas aceptaciones de riesgo, filtros,
`ignore-unfixed`, cambios IAM ni permiso de despliegue.

Los operadores nuevos conservan sus hallazgos SAST para revisión individual;
la justificación de permisos de directorio o de un subprocess acotado no
constituye una aceptación. F-SAST-EXEC histórico no cubre nuevos llamadores
de preparación, transporte o experimentos locales.

El informe nativo de operadores/launcher/cliente conserva **7 LOW y 1 MEDIUM**
(SHA-256 `69a135df1d50d7fd2f3bf37a66c9cac4e7a1bad4230d6791e50603898abba323`):

| Regla | Resultado actual y revisión pendiente |
| --- | --- |
| B105, 5 LOW | Nombres de variables, rutas/IDs de secretos y literal de SCRAM. Son identificadores/configuración; cada alerta sigue visible y sin excepción. |
| B404/B603, 2 LOW | Import y ejecución de subprocess del operador nuevo. Requieren revisión propia; la aceptación histórica no se transfiere. |
| B103, 1 MEDIUM | Directorio raíz `0710`: acceso de recorrido para el grupo postgres. El journal privado continúa `0700` y los ficheros secretos `0600`; esta finalidad no acepta el finding automáticamente. |

Ese informe no escanea el nuevo helper del ensayo de fuentes ni reemplaza
la evidencia separada del transporte de la captura GUEST.
