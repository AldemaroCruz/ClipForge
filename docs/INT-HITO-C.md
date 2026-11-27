# ClipForge INT · Hito C

## C00 · Base comprobada

La revisión inicial del portal y la rama de entrega `ci/bootstrap-sec03`
coincidían en `2b7b513e7892772b2d5fe222e9dee8c429f3a6e5`. El frontend
`clipforge-int-beta-00036-cp5` y la API `clipforge-int-beta-api-00037-g59`
reciben el 100 % de su tráfico. El job `clipforge-int-worker` está en
generación `32` y cada ejecución tiene 2 vCPU, 4 GiB y 1.200 s.
[Entrega anterior](https://github.com/AldemaroCruz/ClipForge/actions/runs/45838550340)

| Componente | Implementación de partida | Alcance del Hito C |
|---|---|---|
| Límites | 300 MiB, 20–1.200 s, MP4 H.264/AAC y 1920 px por lado. Un trabajo activo por cuenta, cuatro plazas de admisión y tres procesamientos simultáneos. | Validar 2.147.483.648 bytes en la reserva y en el objeto confirmado. Medir tres medios representativos de tamaño cercano al límite. |
| Carga y procesamiento | Sesión reanudable privada, partes de 8 MiB y confirmación idempotente. Descarga al scratch por generación, lease del worker y publicación con fence. | Medir reanudación sobre la misma sesión e inventariar memoria y temporales. El almacenamiento local de Cloud Run usa la memoria de la instancia. |
| Subtítulos | El editor por clip guarda cues y estilo versionados. El worker genera sólo el derivado asociado a la revisión. | Agregar un acceso directo para corregir texto y descargar MP4, SRT y WebVTT. |
| Recortes | Selección sobre el original con tiempos en segundos y subtítulos relativos al recorte. | Revisar ambos bordes con fotogramas reales y comprobar la sincronía del archivo exportado. |
| Persistencia y eliminación | PostgreSQL conserva proyectos y revisiones. La eliminación lógica bloquea resultados tardíos y la limpieza de GCS continúa en segundo plano. | Conservar idempotencia, aislamiento, eliminación inmediata y limpieza de temporales al interrumpir un worker. |

INT conserva OpenAI con `gpt-6-luna` y el tope global configurado por
defecto de 10 llamadas reservadas por día UTC. El alcance de pruebas de C01–C03
usa proyectos y cuentas sintéticas. La ruta de cargas grandes conserva
la sesión reanudable directa a GCS. [Contrato de Cloud Run](https://docs.cloud.google.com/run/docs/container-contract) · [Subidas reanudables de GCS](https://docs.cloud.google.com/storage/docs/performing-resumable-uploads)

El primer build de C02 recibió HTTP 404 al descargar el pin retirado de
`libexpat1` para Noble. Se verificaron la versión sustituta
`2.6.1-2ubuntu0.7` y el SHA-256 del índice firmado de Ubuntu.
[Primer build](https://github.com/AldemaroCruz/ClipForge/actions/runs/45873369459) · [Paquete Ubuntu Noble](https://packages.ubuntu.com/noble-updates/libexpat1)

## Candidata y reanudación en INT

El 26 de noviembre de 2026 se seleccionó la corrida
[`45876391413`, intento 1](https://github.com/AldemaroCruz/ClipForge/actions/runs/45876391413)
del workflow `int-hito-b.yml` para
`abe806711666dd75af6ad628f6192e07db3a5072`. Su padre directo es
`8a49ba47a52c90342f8436878d6b872c11020af4`, que ya incluye C02, C03 y
el pin actualizado. C01 agrega el límite, la transferencia reanudable,
la instrumentación y las pruebas de concurrencia. Un único despliegue
de esa candidata verifica los tres incrementos.

| Corrida | Decisión y artefactos |
|---|---|
| [45875033327](https://github.com/AldemaroCruz/ClipForge/actions/runs/45875033327) | Cancelada durante la espera de aprobación de `deploy`. Sus resultados e imágenes siguen vigentes como evidencia de su propio SHA. Validación [15145122337](https://github.com/AldemaroCruz/ClipForge/actions/runs/45875033327/artifacts/15145122337) y OCI [15144214329](https://github.com/AldemaroCruz/ClipForge/actions/runs/45875033327/artifacts/15144214329). |
| [45876391413](https://github.com/AldemaroCruz/ClipForge/actions/runs/45876391413) | Primera candidata de C01–C03. `frontend` y `api` pasaron. `deploy` migró y abrió el portal. La prueba buscó un atributo ausente en «Corregir texto» y venció antes de enviar el PUT. Se restauró la base. Quedan los OCI [15146133485](https://github.com/AldemaroCruz/ClipForge/actions/runs/45876391413/artifacts/15146133485), [validación 15145558753](https://github.com/AldemaroCruz/ClipForge/actions/runs/45876391413/artifacts/15145558753) y [recibo del intento](https://github.com/AldemaroCruz/ClipForge/actions/runs/45876391413/artifacts/15164223544). |
| [45921581845](https://github.com/AldemaroCruz/ClipForge/actions/runs/45921581845) | `df593f354730c56e945121cea8809ffcbf3c0bc7` corrige el selector rápido, el estado HTTP 202 y el nombre del enlace VTT editorial. Pasaron el MP4 y los subtítulos corregidos. La selección breve devolvió cero propuestas para 74 rangos elegibles y se restauró la base. [Recibo del intento](https://github.com/AldemaroCruz/ClipForge/actions/runs/45921581845/artifacts/15165459107) |
| [45924575800](https://github.com/AldemaroCruz/ClipForge/actions/runs/45924575800) | `3996c23c657bd3f220d08b9b9b2f8934236a5939` incorpora un único reintento breve, con nuevo consentimiento, para una respuesta real vacía. Se comprobaron C01, C02 y C03 durante el despliegue. El flujo completo falló después con HTTP 429 no JSON en el POST de previsualización editorial. [Recibo del intento](https://github.com/AldemaroCruz/ClipForge/actions/runs/45924575800/artifacts/15168803647) |
| [45932688939](https://github.com/AldemaroCruz/ClipForge/actions/runs/45932688939) | `34483012f5626f8d4e24d194a403f0c3339120e9` acota el reintento de rango y usa WIF renovable. Frontend, API, publicación y migración pasaron. GitHub cerró el job al perder comunicación con el runner administrado durante la aceptación, el 27 de noviembre a las 04:43:41 UTC. El paso de conservación de evidencia quedó pendiente y el portal seguía sirviendo esa candidata. [Job de despliegue](https://github.com/AldemaroCruz/ClipForge/actions/runs/45932688939/job/140291299219) |
| [46002851221](https://github.com/AldemaroCruz/ClipForge/actions/runs/46002851221) | `d39e61acf4a89f8dd4d738184808afb4b674eb05` agrega recibos por etapa. Frontend, pruebas de API, Gitleaks y la revisión Bandit de INT pasaron. El build se detuvo con 404 en los cuatro paquetes Kerberos Noble `1.20.1-6ubuntu2.10`. [Validación conservada](https://github.com/AldemaroCruz/ClipForge/actions/runs/46002851221/artifacts/15198503797) |
| [46004291744](https://github.com/AldemaroCruz/ClipForge/actions/runs/46004291744) | `bd344e9456c197819946383e7486600253d959cc`, intento 1. Frontend y API aprobaron, incluido el build y escaneo de los OCI. El único `deploy` espera revisión en `int` sin runner asignado. [OCI 15201366295](https://github.com/AldemaroCruz/ClipForge/actions/runs/46004291744/artifacts/15201366295) · [Validación 15200657301](https://github.com/AldemaroCruz/ClipForge/actions/runs/46004291744/artifacts/15200657301) |

El recibo de validación liga el SHA a la imagen web
`sha256:b8b8f544142ab0ed73099b1056667e76d6b4b5253833cdffdb420cb8bad07ef5`
y a la imagen del worker
`sha256:edffb991cf91f0a0ce79107070dd14170d1f0758dab249bb8d3516283e4bed4f`.
Son los digest candidatos. Los OCI vencen el 3 de diciembre de 2026
a las 18:59 UTC.

Durante la interrupción inicial la primera candidata quedó esperando en
GitHub. Se recuperó esa misma corrida con la revisión de `AldemaroCruz`
y una consulta de sólo lectura que confirmó 0 de 10 reservas usadas.
Cada candidata posterior se ejecutó por separado en el mismo grupo
`clipforge-int-hito-a-delivery`.

El tercer despliegue llegó a las revisiones `clipforge-int-beta-00040-8lw`
y `clipforge-int-beta-api-00041-w58`, worker generación 37 con
`sha256:13fabbfc3087cbef90f5163505c60672618591ad1e1e85d1cb0a02e32941d1b8`.
El último paso editorial recibió HTTP 429 en el frontend y el token
estático venció antes de la reversión automática. Se restauró el portal
con la sesión administrativa y se verificó el commit base. La corrección
posterior mantiene la revisión protegida y los artefactos de su propia
corrida. Permite un solo reintento del mismo POST de rango ante 429
no JSON y usa las credenciales WIF renovables de la misma identidad
durante la aceptación y su reversión. El recibo de la corrida anterior
reúne evidencia real y queda fuera del contrato de replay del workflow.

El siguiente build actualiza únicamente los cuatro paquetes Kerberos
afectados a `1.20.1-6ubuntu2.12`. Se verificaron las firmas de los
índices Noble Updates y Noble Security, y la identidad y el SHA-256 de
cada paquete amd64. La candidata nueva se valida con los gates vigentes
y requiere sus propios recibos de aceptación.
[Índice firmado de Noble Updates](https://archive.ubuntu.com/ubuntu/dists/noble-updates/InRelease)

### Punto de continuación

Al recuperar el acceso, `34483012…` servía el frontend
`clipforge-int-beta-00042-p29` y la API `clipforge-int-beta-api-00043-chv`
al 100 %. Ambas revisiones usaban
`sha256:cb741be3a8724d417c41980a19da2df7be27f366c1b22a0348d86f2f6b5c49e3`.
El worker generación 39 usaba
`sha256:396ab7506b2d8c2626770926829be8e600b27f3d79299c27887e255ec19b91f1`
y el migrador generación 28 tenía el digest web candidato. Coinciden con el
recibo nativo. La migración terminó antes de la prueba. El runner perdió
comunicación antes del paso de publicación de evidencia y quedó pendiente
la reversión. [Recibo nativo de la candidata](https://github.com/AldemaroCruz/ClipForge/actions/runs/45932688939/artifacts/15170025636)

Entre `3996c23` y `3448301` cambiaron el workflow, el arnés de navegador y
la documentación. La aplicación, los locks y la infraestructura quedaron
idénticos en fuente. Los dos builds tienen digest OCI distintos. La
comparación de ambas parejas de imágenes confirmó los mismos archivos de
aplicación, binarios de medios, modelos y paquetes. Las pruebas funcionales
de `3996c23` se conservan como evidencia de esas funciones. El contrato
vigente exige un recibo completo de la candidata que se promueva.
[Validación de 3996c23](https://github.com/AldemaroCruz/ClipForge/actions/runs/45924575800/artifacts/15165314861) · [Validación de 3448301](https://github.com/AldemaroCruz/ClipForge/actions/runs/45932688939/artifacts/15170025636)

Se completó la reversión de `45932688939` el 27 de noviembre. Se
comprobó que el esquema y el formato de las tareas permiten restaurar la
base, y que no había leases activos. La exportación histórica en cola
es anterior al incidente y conservó su estado. INT sirve
`2b7b513e7892772b2d5fe222e9dee8c429f3a6e5` con las dos revisiones
descritas en la sección de reversión al 100 %. La API directa sigue
protegida. El worker restaurado quedó en generación 40, con 2 vCPU,
4 GiB, una tarea, paralelismo 1, 1.200 s y cero reintentos. Usa OpenAI
`gpt-6-luna`, timeout 40 s y la referencia al secreto versión 1. El
migrador quedó en generación 29 con su pin anterior. Se conservó su
última ejecución exitosa y la restauración del pin se hizo sin otra
migración.

Se eliminaron lógicamente los tres proyectos QA de `45924575800` desde
sus cuentas. El mecanismo normal de administración desactivó las tres
cuentas y revocó las diez sesiones registradas. La comprobación de
las 12:51 UTC observó 51 generaciones pendientes por retención de GCS
en los tres proyectos, con el primer reintento el **3 de diciembre a
las 20:42 de Guatemala**. El estado físico permanece diferido. El
recibo agregado de la limpieza de cuenta y proyecto tiene SHA-256
`06bff10090165e9e26eddef170627aec344334cd811236c99a70d4fe47febd44`.

El workflow conserva los jobs `frontend`, `api` y `deploy`. La aceptación
publica artefactos separados al terminar los pasos de video breve,
persistencia, altas sintéticas, carga C01, cortes C03 y editorial. Cada
artefacto de etapa contiene el rollout verificado y su recibo. Los
recibos de capacidad se vinculan a la corrida, intento, SHA, revisiones
y modelo. Las credenciales de los creadores sintéticos permanecen en
el directorio privado del mismo runner. El paso de reversión usa la
identidad WIF protegida y restaura también el pin del migrador.

### Aceptación de selección con IA

El límite efectivo es 10 reservas diarias compartidas. El API calcula
`day_utc` a partir de UTC al registrar el consentimiento y la selección.
PostgreSQL aplica el límite bajo el bloqueo de admisión y conserva la
cuenta del día incluso si se elimina el proyecto. La consulta agregada de
sólo lectura del 26 de noviembre confirmó 10 de 10 usadas. El siguiente
día comienza el 27 de noviembre a las 00:00 UTC, el 26 a las 18:00 en
Guatemala. La fecha cambia qué reservas se computan; consultar
disponibilidad por este mecanismo consume cero llamadas.

La aceptación base hace una selección consentida con un original breve
y tres en paralelo con originales largos, con OpenAI `gpt-6-luna`.
Cuatro es el mínimo; una selección larga sin propuestas puede requerir
nuevo consentimiento y otra reserva. C01 cambia los originales y puede
cambiar transcripciones y rangos que llegan a la selección. C02 guarda
una variante de subtítulos sobre el clip existente; la prueba verifica
que la corrección conserva transcripción, selección y otros clips.
C03 modifica la revisión de bordes y el render de los rangos de origen;
se comprueban los archivos realmente exportados. El contrato de
reutilización del workflow vincula la evidencia previa a padres y cambios
específicos. La evidencia de `45924575800` registra cinco llamadas y cinco
respuestas reales, una breve, tres largas con 2,319 s de solapamiento y
un reintento consentido de una larga que había devuelto cero propuestas.
Los cuatro recorridos produjeron una propuesta válida cada uno. El
intento anterior había consumido una llamada breve.

La consulta de recuperación del 27 de noviembre a las 12:51 UTC
confirmó **7 de 10 reservas usadas** después de la limpieza de las
cuentas. Quedó una reserva en documentos y seis en el registro de
proyectos eliminados. El recorrido completo requiere al menos cuatro
reservas disponibles para una aceptación nueva. La ventana siguiente comienza
el 28 de noviembre a las 00:00 UTC, el **27 a las 18:00 de Guatemala**.
La consulta de las 13:12 UTC confirmó el mismo total. Al abrir la
ventana se repite la consulta de sólo lectura. Con al menos cuatro
reservas disponibles, el revisor `AldemaroCruz` puede usar
**Review deployments → int → Approve and deploy** únicamente en
`46004291744`. Los OCI de su propio intento vencen el 4 de diciembre
a las 13:17 UTC. El workflow vuelve a verificar el SHA y los OCI
antes de usar WIF. Los artefactos por etapa quedarán en esa misma
corrida.

## Aceptación

Las mediciones de esta entrega se registran por incremento en el
[backlog](BACKLOG.md). Los resultados de límites y capacidad se atribuyen a
las revisiones donde se observó el recorrido completo.

### C01 · Entrada de hasta 2 GiB

La candidata mantiene la carga reanudable en partes de 8 MiB. Antes de
encolar se compara el tamaño declarado con el tamaño y generación del
objeto en GCS. El worker vuelve a validar el límite antes de descargar el
original. El supervisor retira su directorio temporal incluso cuando
debe terminar el proceso hijo.

El medio sintético local medido tiene 2.116.430.544 bytes, 1.200 segundos,
28.800 fotogramas H.264 de 1280×720 y audio AAC con voz sintética. Sus
bytes provienen de la codificación de fotogramas y audio. La prueba
remota usa tres cargas independientes de ese fixture, interrumpe el
segundo fragmento de una, repite la confirmación y vuelve a comprobar la
persistencia desde cada nueva sesión. El recibo vincula sólo los trabajos
sintéticos con los eventos `worker_resources`. Esos eventos distinguen
el máximo muestreado de scratch y memoria por tarea, RSS del hijo y el
pico del cgroup de la ejecución completa.

El job vigente tiene una tarea por ejecución y paralelismo 1. Cada
instancia supervisa un proceso de trabajo por vez, con los subprocesos de
medios que éste necesite. El límite de tres medios simultáneos corresponde
a ejecuciones distintas. La candidata conserva 2 vCPU, 4 GiB y 1.200 s.
Los originales y derivados persistentes están en el bucket privado de
medios; PostgreSQL conserva las referencias. Los temporales de trabajo
usan el filesystem escribible de Cloud Run y se retiran al finalizar.

En un contenedor aislado con 4 GiB, 2 CPU, sin swap y sin red, FFmpeg 9.1
y Whisper Tiny con pesos verificados procesaron ese video y generaron
cinco clips con audio, subtítulos incrustados y SRT/WebVTT. El recorrido
local tardó 132,407 s. La copia local y verificación MD5 tomaron
10,695 s, la transcripción 40,268 s y el render 80,910 s. El pico del
cgroup fue 3.704.832.000 bytes y el máximo muestreado de temporales fue
2.167.486.700 bytes. El pico corresponde al contenedor entero y puede
incluir páginas de archivos y memoria de sus procesos. El scratch suma
los tamaños lógicos de los archivos presentes en el directorio de la tarea
en cada muestra, incluido el original local. Ambas mediciones pueden
superponerse y sus máximos corresponder a distintos instantes. La copia
local mide otro recorrido que la transferencia desde GCS.
[Filesystem de Cloud Run](https://docs.cloud.google.com/run/docs/container-contract#file-system)

En `45924575800`, INT publicó el límite de 2.147.483.648 bytes y rechazó
2.147.483.649 bytes en la reserva del servidor. Tres creadores cargaron y
procesaron sendos MP4 H.264/AAC de **2.116.336.669 bytes y 1.200 s**. Una
carga reanudó la misma sesión desde 8.388.608 bytes. Las tres confirmaciones
repetidas conservaron su ID y su lista de clips. Cada cuenta verificó
cinco MP4 con audio y subtítulos, SRT y VTT, recuperación tras volver a
iniciar sesión y denegación de acceso cruzado.

| Cuenta sintética | Carga (s) | Confirmación a resultado (s) | Descarga del worker (s) | Transcripción (s) | Render (s) | Publicación (s) |
|---|---:|---:|---:|---:|---:|---:|
| 1 | 264,432 | 318,052 | 30,969 | 36,860 | 154,512 | 2,394 |
| 2 | 264,644 | 321,839 | 30,720 | 37,601 | 156,855 | 2,806 |
| 3 | 264,277 | 479,987 | 31,241 | 101,326 | 249,598 | 3,013 |

Las tres ejecuciones pasaron en Cloud Run, con 228,319 s de intersección
entre toma y finalización de la tarea. Durante ese solapamiento el login
tomó 0,871 s, la consulta de estado 0,128 s y la navegación probada
0,365–0,645 s. El máximo muestreado de scratch fue 2.167.344.550 bytes
y el de RSS del hijo 1.494.818.816 bytes. El pico total de cgroup
quedó sin dato por ejecución. El worker tenía 2 vCPU, 4 GiB y una tarea
por ejecución. El resultado corresponde a esta carga sintética y a
las revisiones probadas. Cloud Monitoring publica la métrica de memoria
del job sin una etiqueta por ejecución que permita asignar a cada caso
su pico total. [Recibo de la prueba](https://github.com/AldemaroCruz/ClipForge/actions/runs/45924575800/artifacts/15168803647) · [Métricas de Cloud Run](https://docs.cloud.google.com/monitoring/api/metrics_gcp_p_z)

### C02 · Corrección rápida

En **Mis trabajos**, abre un clip automático, pulsa **Corregir texto** y
edita la frase. **Guardar y exportar** crea una variante del clip con los
tiempos y el estilo existentes. El acceso a **Editar subtítulos** conserva
los controles de tiempos y estilo. La prueba local de Chromium usó
datos sintéticos y verificó persistencia de la corrección al recargar y
la disponibilidad de MP4, SRT y WebVTT para la nueva revisión.

En INT se corrigió «recorte» a «fragmento» y se comprobó el cambio en
MP4, SRT y WebVTT. Se conservaron los tiempos, estilo y otros dos clips,
así como el análisis del original y la selección. El texto y el resultado
persistieron luego del reemplazo de la revisión y el nuevo inicio de sesión.
[Recibo de la prueba](https://github.com/AldemaroCruz/ClipForge/actions/runs/45924575800/artifacts/15168803647)

### C03 · Bordes del recorte

En **Propuestas por IA y edición**, **Revisar inicio** y **Revisar final**
reproducen ventanas alrededor de los bordes. Usa **Usar este fotograma
como inicio** o **Terminar antes de este fotograma** para ajustar los
límites. **Aplicar rango** y **Aprobar y exportar** guardan y generan la
variante correspondiente.

La prueba local con medios sintéticos VFR de cadencia base 24000/1001
exportó los intervalos 180,123–184,600 s y 202,017–207,978 s. Comparó
fotogramas, PTS, un marcador de audio y los subtítulos descargables. Con
FFmpeg 9.1 observó un error de PTS de 0 ms en los dos recorridos, con un
intervalo máximo entre fotogramas de 83,417 ms. La aceptación remota usa
además voz sintética para conservar el recorrido real de transcripción.

El recibo de INT confirma los mismos dos intervalos. Los MP4 descargados
duraron 4,519792 s y 5,982459 s, con 86 y 114 fotogramas. El mayor intervalo
entre fotogramas fue 83,417 ms. El desvío máximo observado de PTS y el
cambio de sincronía audiovisual fueron 0 ms en las comparaciones. Los
subtítulos se comprobaron en los MP4 y en SRT y VTT.
[Recibo de la prueba](https://github.com/AldemaroCruz/ClipForge/actions/runs/45924575800/artifacts/15168803647)

### Reversión

La base observada para revertir esta entrega es
`clipforge-int-beta-00036-cp5` y `clipforge-int-beta-api-00037-g59`, ambas
al 100 %, y el worker en
`sha256:3d25e9bfae8c93aa4e6a54bec2835560afb71cfd6fcad3bfde1a83c744158bc4`.
Antes del apply, el workflow registra el estado efectivo y las referencias
de configuración editorial del worker en `previous-live.json`. Ante
un fallo de aceptación restaura el worker con su configuración y el tráfico
de ambas revisiones, y verifica salud y commit público. El mismo plan
actualiza `clipforge-int-beta-migrate`. Para completar una reversión,
verificar también el pin de ese job y, si cambió, restaurar su imagen
previa mediante el procedimiento de INT. Su generación 21 usaba
`sha256:af93f0cefa4d40d449744d92a86b9289bccd9fe6ef7c44e099b39d151c53f8a7`,
el mismo digest de las revisiones web anteriores. C01–C03 conservan el
esquema. [Entrega y reversión](INT-HITO-B.md#entrega-y-reversión)
