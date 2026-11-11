# AUTH-02: recuperación local y auditoría de cuentas

Implementación para una candidata nueva con PostgreSQL y datos sintéticos.
La instalación v0.4.2 y la candidata AUTH-01 del propietario permanecen fuera.
Sin correo, servicios pagos, Pro/ESM, recuperación de administradores, MFA,
impersonación o cambio de roles/propietarios. Seguridad y release siguen bloqueados.

## Flujo para el administrador y el usuario

1. El administrador entra a **Mi cuenta → Recuperación local**. Selecciona una
   cuenta normal activa y vuelve a introducir su propia contraseña. Backend
   comprueba sesión, permisos, CSRF y reautenticación con límites persistentes.
2. **Emitir código** invalida cualquier código pendiente anterior. No cambia
   la contraseña ni inicia sesión como la cuenta objetivo. El código tiene
   256 bits aleatorios, se almacena únicamente como SHA-256, caduca a los
   15 minutos y solo se puede consumir una vez.
3. **Mostrar una vez** permite su entrega manual por un canal privado fuera
   de la aplicación. Verifica personalmente al destinatario. No envíes el
   código como enlace, captura, ticket, log o mensaje en este chat. Bórralo de
   pantalla al terminar; la interfaz lo elimina al salir u ocultar la página.
   No existe una consulta posterior para volver a recuperarlo del servidor.
4. El destinatario abre **Tengo un código de recuperación** desde el login,
   introduce el código y una contraseña nueva, y la confirma. El código se
   envía en el cuerpo POST, nunca en URL o localStorage. La solicitud exige
   origen y desafío CSRF previo, sin autenticación simulada.
5. El servidor consume el código, cambia la contraseña y revoca todas las
   sesiones anteriores en una transacción. Después hay que iniciar sesión
   normalmente. No se reactiva una cuenta desactivada ni se recupera un admin.

Si abandonas la pantalla mientras se emite el código o pierdes la respuesta,
emite uno nuevo para invalidar el anterior; no hay un endpoint de reconsulta.
El destinatario se fija al enviar y queda identificado junto al código. Una
respuesta tardía no vuelve a mostrarlo después de ocultar/salir de la página.
Un fallo al refrescar la lista de auditoría no borra la respuesta de emisión.

Los límites persistentes son cinco intentos por identidad y treinta por cliente
en quince minutos, separados por propósito; también cuentan los intentos válidos.
No se confía en X-Forwarded-For como identidad del cliente. Un navegador que ya
tiene sesión puede usar su CSRF vigente para consumir el código; tampoco recibe
una sesión como la cuenta recuperada y sus cookies se eliminan tras el éxito.

**Poder adicional:** quien posea el código puede establecer la contraseña de
esa cuenta y acceder a su espacio después del login. Aunque la administración
no recibe acceso directo a proyectos, un administrador que emite y utiliza el
código podría asumir la cuenta normal. La verificación del destinatario y la
confianza en administradores son necesarias; la auditoría no impide ese abuso.
Este poder queda registrado como riesgo, no aceptado ni apto para publicación.

## Auditoría y consistencia

Mi cuenta ofrece una tabla administrativa de solo lectura, paginada, con filtros
de acción, resultado y cuenta objetivo. Eventos: `user.created`,
`user.deactivated`, `recovery.issued`, `recovery.consumed`, `password.changed`.
Cada fila conserva actor, objetivo, fecha UTC, resultado y correlación. No
incluye contraseñas, hashes de contraseña, códigos/hash de recuperación,
cookies, tokens, connection strings ni contenido editorial.
El restablecimiento de contraseña con código se registra como
`recovery.consumed`; el cambio con contraseña actual como `password.changed`.
Un consumo anónimo tiene actor nulo; si había sesión válida conserva el actor
conocido, sin fingir que sea la cuenta objetivo.

La acción sensible y su evento exitoso comparten transacción: si la escritura
del evento falla, se revierte la operación. Los errores y límites no exponen
secretos. No hay endpoints para editar o borrar eventos; esto no garantiza
inmutabilidad frente al propietario de PostgreSQL o acceso SQL privilegiado.
No se fabrican eventos retrospectivos de acciones anteriores a AUTH-02.

La migración nueva sucede a `auth01_0001`; su DDL histórico se conserva. Las
pruebas de actualización parten de fixtures AUTH-01, nunca de cuentas o datos
del propietario. No ejecutar migraciones sobre sus volúmenes en esta entrega.

## Matriz de permisos y pruebas requeridas

| Operación | Anónimo | Usuario normal | Administrador |
| --- | --- | --- | --- |
| Emitir código | Denegado | Denegado | Sesión + CSRF + contraseña actual; solo cuenta normal activa |
| Consumir código | Código válido + preauth CSRF | Mismo contrato, sin asumir otra identidad automáticamente | Mismo contrato; ningún código para recuperar admins |
| Leer/filtrar auditoría | Denegado | Denegado | Sesión válida, solo lectura |
| Leer proyecto de otra cuenta | Denegado | Denegado | Denegado por administración; recuperación introduce el poder descrito arriba |
| Editar/eliminar auditoría por API | Sin endpoint | Sin endpoint | Sin endpoint |

Pruebas previstas sobre PostgreSQL real: permisos, CSRF/reautenticación y límites;
códigos inválidos/vencidos/revocados/reutilizados y reemplazo; dos consumos
simultáneos con un único éxito; revocación de sesiones; cuentas desactivadas y
administrativas; migración/persistencia; rollback si falla auditoría; ausencia de
secretos en logs/auditoría/respuestas no autorizadas; separación de proyectos.
El recorrido browser real de recuperación/auditoría se añade a los seis previos
y a AUTH-01. Las fixtures negativas de contrato CI no acreditan ejecución browser.

## Resultados locales de la candidata 2

Expediente `.ci-local/auth02-88fa2cf5/`. Se usaron contexto curado verificado de
121 archivos, recursos/credenciales sintéticos propios y red Docker **internal**
sin salida externa para integrar PostgreSQL. Los scanners e inventarios usaron
`--network none`; las descargas se prepararon por separado. No se publicaron
puertos del host ni se montó la raíz del repositorio. La candidata del propietario
y el servicio operativo no se reconstruyeron, migraron o reemplazaron.

| Control ejecutado | Resultado real |
| --- | --- |
| Suite completa | **736/736**, sin fallos, errores, skips, expected failures o unexpected successes |
| Inventario | 681 IDs previos conservados; 55 altas; cero retirados/duplicados |
| Altas | 37 PostgreSQL recuperación/auditoría; 3 contratos UI Node/DOM sintéticos; 9 wrapper CI y 6 validador CI |
| Compatibilidad de IDs anteriores | Dos tests de migración ajustan expectativas a la revisión nueva; conservan sus IDs y controles de datos/revisiones desconocidas |
| Checks originales | **11 aprobados**, incluidos FFmpeg/ffprobe, dependencias, runtime, render, subtítulos/fuentes y branding |
| Browser previo | **6 aprobados** en tanda secuencial: 5 HTTP directo y smoke simulated_fetch; ASR/LLM siguen siendo fixtures |
| Browser AUTH-01 | **7 pasos aprobados**, HTTP y PostgreSQL reales, reinicio real |
| Browser AUTH-02 | **8 pasos aprobados**, HTTP/UI y PostgreSQL reales; sin autenticación simulada |
| Migración y aislamiento | Salida0; PG sin puerto publicado, rol aplicación propio no-superuser, capacidades cero/NNP y salida externa bloqueada |
| JavaScript | Cinco archivos, sintaxis aprobada con Node de la imagen; contratos UI sintéticos separados de la aceptación real |
| Actionlint | 1.7.12 obligatorio: workflow válido salida0 y fixture inválida salida1 |
| Bandit | **39 findings, 36 LOW/3 MEDIUM, cero errores**; siguen bloqueantes |
| Gitleaks de la selección final | **1 finding bloqueante** en el SHA256 público del DDL congelado; verificación específica abajo, sin excepción |
| Trivy CI/browser/PG | Gates HIGH/CRITICAL con salida1 por findings, SBOM salida0 y tres identidades verificadas |
| Limpieza | Recursos del primer y segundo intento retirados por su identidad/etiquetas; recibos sin recursos ni archivos privados restantes |

Los 37 tests PostgreSQL cubren permisos, CSRF/reautenticación/límites,
validación/expiración/revocación/reutilización/reemplazo y consumo simultáneo
con un único éxito; revocación de todas las sesiones; rechazo admin/desactivados;
persistencia/migración desde DDL AUTH-01 congelado; rollback real mediante trigger
si falla auditoría; privacidad de logs/auditoría/respuestas y separación de
proyectos después de recuperar. No se compara ni migra una base del propietario.

Pasos browser nuevos: `recovery_admin_reauthentication`, `recovery_issue`,
`recovery_replace`, `recovery_process_restart`, `recovery_consume`,
`recovery_session_revocation`, `recovery_single_use`, `recovery_audit_privacy`.
Se conserva además el contrato obligatorio AUTH-01 y sus seis escenarios previos.
La prueba negativa del gate rechaza informes ausentes, parciales, simulados,
secretos inesperados, identidades incorrectas y fallos/timeout. Esto no convierte
fixtures sintéticas de contrato en ejecuciones reales de navegador.

Cobertura de 49 fuentes app/scripts: líneas **5420/6576 = 82,42092457420925 %**,
ramas **1354/1874 = 72,25186766275347 %**, combinada **80,16568047337279 %**.
Mide unittest con mocks/threads explícitos; no mide JavaScript, navegación,
subprocesos nativos ni AUTH HTTP/PG en otros procesos. Sin omit, exclusiones o
umbral nuevo. No se deduce seguridad de estos porcentajes.

Incidencias conservadas:

- Docker Desktop estaba cerrado; se abrió con su configuración existente. Se
  inspeccionaron únicamente montajes/comandos de las instancias conservadas:
  no montan el código ni usan reload. No se leyó su entorno ni sus secretos.
- El primer inventario PG rechazó un prefijo local antes del probe. Se corrigió
  solo el lanzador temporal; el intento fallido se conserva.
- Suite candidata1: 736 ejecutados, 11 checks aprobados, dos fallos de expectativa
  QA (Origin anónimo y cookie de borrado). Se corrigieron esas pruebas sin
  reducir seguridad y se probó el conjunto final en candidata2. El ajuste `END;`
  de la función trigger fue preventivo, no causa de un error observado.
- Primera tanda legacy candidata2: workflow no obtuvo health dentro del plazo
  de arranque, con servidor vivo, mientras se ejecutaban suite/exportaciones;
  los otros cinco pasaron. Una única tanda secuencial de los seis pasó en la
  misma imagen, sin ampliar plazos ni modificar código. La contención es una
  hipótesis compatible, no una causa demostrada; ambos resultados permanecen.

## Seguridad, identidades y revisión pendiente

| Imagen final | ImageID | HIGH / CRITICAL / IDs únicos |
| --- | --- | --- |
| CI | `sha256:61d41e02b11c08025e416b9c8c099b93777043c57a4ab8391a861bec7d36edcc` | 281 / 1 / 66 |
| Browser | `sha256:7df5d31b7a898d0b2b4b2134e143f7bc71d1ab62f3866dd77eb386d1b6ee0235` | 283 / 1 / 68 |
| PostgreSQL | `sha256:8bca9649e52d948114ccc8164b55b7ab26b64e729893e420114bb5c87bf7c7cc` | 147 / 2 / 62 |

Scans nuevos de las tres imágenes con Trivy0.76.2 y una DB recién preparada,
SHA256 `4c2300c4576c99501ddad6911f1ced5bcd8ddaf65d925f82205a436154b20e61`,
schema2, UpdatedAt `2026-11-11T13:00:47.186797699Z`, DownloadedAt
`2026-11-11T18:37:45.893971166Z`. Se congeló y comprobó su hash antes/después,
montada RO. No se usaron excepciones, VEX, ignore-unfixed o cambios de severidad.
Los paquetes/versiones inventariados coinciden con el run anterior; los reportes
y la DB se identifican de nuevo, sin atribuir el scan anterior a estas imágenes.

Son 715 filas y 97 identificadores distintos en la unión. CRITICAL:
libxml2/CVE-2026-6653 en las tres imágenes, y Go stdlib/CVE-2025-68121 dentro de
gosu en PostgreSQL. PostgreSQL distingue motor18.6 sin findings atribuidos en
estos reportes, 123 filas OS y 26 Go; no se atribuyen todas al servidor SQL.
Las severidades y fuentes originales permanecen en el registro de riesgos.
No se reabre SEC-05 ni se inicia una remediación general.

Gitleaks8.30.1 detectó `generic-api-key` en
`tests/test_auth_recovery.py:41`, constante `FROZEN_AUTH01_DDL_SHA256`.
Se recalculó el SHA256 de las 13 sentencias DDL públicas del commit de referencia
`7fe3a486…` usando el mismo algoritmo del test y coincide exactamente: no es una
credencial de ejecución. La prueba específica queda en
`.ci-local/auth02-88fa2cf5/gitleaks-ddl-proof.json`. Se conserva el finding y su
rechazo; no se renombró/ocultó el valor ni se añadió allowlist, exclusión o
aceptación para obtener verde. Esa disposición del contrato de secretos requiere
revisión separada antes de aprobar CI; no afecta al éxito funcional observado.

El gate local final debe seguir rechazando findings de Bandit, Gitleaks y las
tres imágenes Trivy. No se interpreta como un fallo nuevo de autenticación o
evidencia ni se utiliza para omitir sus controles. AUTH-02 todavía no se ejecutó
en GitHub: no hubo push del código y no se autoriza release/despliegue.

El cierre CI-AUTH-01 se registró por separado en commit
`f53b81536bd2796ce3c65c90b48dce86bd5076f6`, tras escanear los 164 blobs exactos
del índice con Gitleaks 8.30.1, sin hallazgos. No hubo push. El código AUTH-02
permanece sin commit hasta revisión. Los reportes históricos conservan sus
fuentes/identidades; no acreditan estas imágenes nuevas ni aceptan riesgos.

## Clasificación puntual revisada de Gitleaks

El propietario aprobó únicamente el checksum público de la constante congelada
en `tests/test_auth_recovery.py`. Los informes originales y la prueba DDL se
conservan como evidencia histórica; sus flags anteriores no describen esta
clasificación posterior. No se acepta ningún finding Bandit o Trivy.

La configuración versionada [.gitleaks.toml](../.gitleaks.toml) extiende todos
los defaults de Gitleaks8.30.1. La allowlist pertenece solo a `generic-api-key` y
requiere AND entre la ruta exacta en el montaje `/source` y la línea completa,
con la asignación y literal aprobados. No excluye todo el archivo, regla, todos
los checksums o commits. No se modifica el literal ni su uso en el test.

Se usa `--config` explícito tanto en CI como en el escaneo de los blobs del
índice. El recibo de ejecución identifica versión/digest, SHA de configuración,
manifiesto de fuentes y JSON crudo. El validador exige esos vínculos y rechaza
errores, ausencia/parcialidad, tipos incorrectos y cualquier finding restante.
El fingerprint de configuración exige revisión si cambia la clasificación.

`scripts/check_gitleaks_precision.py` ejecuta ocho casos con defaults y con la
configuración: 16 scans reales offline sobre fixtures sintéticas aisladas.
Solo el checksum/asignación/ruta aprobados desaparecen. Otro secreto en el
mismo archivo u otra regla, hash/identificador distinto, otra ruta/nested path y
dos detecciones en la misma línea permanecen bloqueantes. Las comparaciones
contrastan cada finding y sus posiciones, no solo códigos de salida.

La ejecución local de precisión pasó 8/8; no se reconstruyó la aplicación ni se
repitieron sus 736 tests o recorridos. Se reutiliza esa evidencia únicamente
para fuentes de aplicación/fixtures funcionales cuyo contenido sigue idéntico.
Las regresiones de contratos y el nuevo inventario se comprueban por separado;
Actions del nuevo SHA dará su propia evidencia. No se fuerza el contador 736.

Semántica nativa verificada en la
[documentación v8.30.1](https://github.com/gitleaks/gitleaks/blob/v8.30.1/README.md#configuration).
`minVersion` no sustituye la comprobación externa del binario fijado.
El envío autorizado conserva `f53b815`, usa selección explícita, no incluye
SEC-05 ni `.ci-local`, y no aprueba seguridad/release/despliegue. Pro/ESM permanece
aplazado y el presupuesto de nuevos servicios es cero.

Comprobación previa del cierre: 103 tests de contratos únicos pasaron tanto en
discovery top-level como por módulos (dos ejecuciones de los mismos casos,
0 fallos/errores/omisiones). Son fixtures de contrato; no scans de seguridad.
Actionlint 1.7.12 fijado validó el workflow y rechazó el fixture inválido
con códigos 0 y 1, respectivamente, sin red en Docker Desktop. La matriz
Gitleaks sí ejecutó el scanner real. Evidencia propia de esta publicación:
`.ci-local/auth02-publish-ecfd10a5/`. El scan exacto del índice y el run de GitHub
se registran allí con sus identidades; esta comprobación local no los sustituye.

El primer scan real del índice conservó exactamente el falso positivo aprobado
en la línea 41, sin detecciones nuevas. No se publicó ese índice. La fixture
inicial ubicaba la asignación en la primera línea y no cubría el encuadre real:
Gitleaks v8.30.1 conserva el LF anterior en currentLine (location.go42/50 y
detect.go459). Se corrigió solo ese prefijo LF opcional; ruta, regla, asignación
y literal permanecen exactos. No se admite texto/espacios antes o después.
La política corregida tiene SHA256
`877be9355eee66e958e1b453bb59c20302a8cd8bdcd8a7eadb791575483dd054`.
La matriz ampliada pasó 12/12 casos y 24 scans reales: conserva los ocho casos
anteriores, agrega el encuadre no inicial, copia aislada del archivo público
completo (sin ejecutarlo), secreto en línea anterior y secreto como prefijo
en la misma línea. Este último permanece bloqueante. Se conservan
`precision-1.json`, `index-gitleaks-1/` y la prueba del DDL sin alterar.
Fuente oficial: [location.go v8.30.1](https://github.com/gitleaks/gitleaks/blob/v8.30.1/detect/location.go#L42)
y [detect.go](https://github.com/gitleaks/gitleaks/blob/v8.30.1/detect/detect.go#L459).
