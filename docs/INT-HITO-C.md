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
| [45875033327](https://github.com/AldemaroCruz/ClipForge/actions/runs/45875033327) | Candidata anterior, a retirar mientras su `deploy` espera aprobación. Sus resultados y las imágenes quedan asociados a su propio SHA. Validación [15145122337](https://github.com/AldemaroCruz/ClipForge/actions/runs/45875033327/artifacts/15145122337) y OCI [15144214329](https://github.com/AldemaroCruz/ClipForge/actions/runs/45875033327/artifacts/15144214329). |
| [45876391413](https://github.com/AldemaroCruz/ClipForge/actions/runs/45876391413) | Candidata seleccionada. El `deploy` consume exclusivamente `hito-b-candidate-45876391413-1` y el recibo emitidos por su propio job `api`. El historial guarda además `hito-b-validation-45876391413-1` y, al ejecutar el despliegue, `hito-b-int-45876391413-1`. |

En el momento de la selección la corrida nueva esperaba turno en el grupo
`clipforge-int-hito-a-delivery`. Después de que pasen `frontend` y `api`,
el job `deploy` espera en el environment protegido `int` sin ocupar un
runner. El revisor configurado es `AldemaroCruz`. Con al menos cuatro
reservas libres, la acción es revisar y aprobar **sólo** `int` en
**Review deployments → Approve and deploy** de la corrida seleccionada.
GitHub conserva esa espera y las evidencias. El environment carece de
temporizador y el workflow se inicia con `workflow_dispatch`.

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
específicos. La candidata seleccionada ejecuta la aceptación con llamadas
nuevas y conserva la evidencia histórica.

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
local mide otro recorrido que la transferencia desde GCS. El recorrido con
GCS y tres cuentas simultáneas queda para INT. [Filesystem de Cloud Run](https://docs.cloud.google.com/run/docs/container-contract#file-system)

### C02 · Corrección rápida

En **Mis trabajos**, abre un clip automático, pulsa **Corregir texto** y
edita la frase. **Guardar y exportar** crea una variante del clip con los
tiempos y el estilo existentes. El acceso a **Editar subtítulos** conserva
los controles de tiempos y estilo. La prueba local de Chromium usó
datos sintéticos y verificó persistencia de la corrección al recargar y
la disponibilidad de MP4, SRT y WebVTT para la nueva revisión.

### C03 · Bordes del recorte

En **Propuestas por IA y edición**, **Revisar inicio** y **Revisar final**
reproducen ventanas alrededor de los bordes. Usa **Marcar inicio en este
fotograma** o **Marcar final después de este fotograma** para ajustar los
límites. **Aplicar rango** y **Aprobar y exportar** guardan y generan la
variante correspondiente.

La prueba local con medios sintéticos VFR de cadencia base 24000/1001
exportó los intervalos 180,123–184,600 s y 202,017–207,978 s. Comparó
fotogramas, PTS, un marcador de audio y los subtítulos descargables. Con
FFmpeg 9.1 observó un error de PTS de 0 ms en los dos recorridos, con un
intervalo máximo entre fotogramas de 83,417 ms. La aceptación remota usa
además voz sintética para conservar el recorrido real de transcripción.

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
