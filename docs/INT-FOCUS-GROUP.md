# ClipForge INT · guía para el focus group

Ingresá al [portal de ClipForge INT](https://clipforge-int-beta-816643438938.us-central1.run.app) con tu cuenta habitual. Usá un video que puedas compartir con este grupo.

1. Subí el video y abrí el trabajo en **Mis trabajos** cuando termine de procesar.
2. Revisá los clips automáticos. En **Editar subtítulos**, corregí una palabra y comprobá la vista previa. Podés elegir el color con el selector o escribir el HEX exacto.
3. Abrí **Mis logos**. Cargá un PNG estático de hasta 5 MiB y 2048 píxeles por lado. El PNG puede tener transparencia.
4. En **Logo del clip**, activá el logo y elegí el archivo. Ajustá esquina, tamaño, opacidad y margen sobre el encuadre final. La selección inicial coloca el logo arriba a la derecha.
5. Pulsá **Guardar como estilo** junto a los controles de apariencia. Escribí el nombre y guardá el estilo de subtítulos y el logo juntos. Podés aplicar esa plantilla a otro clip desde **Estilos guardados**.
6. Abrí **Elegir fragmento del original**. Ajustá inicio y final, entrá en **Editar y subtitular** y revisá **Encuadre vertical**. Guardá el borrador y exportá.
7. Descargá el MP4 de la variante terminada. Los enlaces SRT y VTT guardan el texto y los tiempos. Para obtener un ZIP, marcá las tarjetas de los clips automáticos, recortes manuales o exportaciones de borradores que quieras incluir. El ZIP reúne los archivos disponibles de las variantes que seleccionaste.
8. Cerrá sesión, volvé a entrar y recuperá el trabajo. Para probar **Eliminar proyecto**, usá un proyecto de prueba. Al confirmarlo desaparece de **Mis trabajos**.

Reemplazar un logo crea una revisión para futuras selecciones. Los borradores, clips y plantillas que ya referencian la revisión anterior conservan su apariencia. Retirarlo quita el logo de la biblioteca y de las plantillas que se apliquen en adelante. Los usos previos y los MP4 ya exportados conservan la revisión guardada.

Enviá tus comentarios por el canal escrito acordado. Incluí el paso, el resultado y una captura si ayuda a identificar el problema.

## Buscar momentos por tema

Disponible en INT en el commit `9e49209aad98f74428b50276836719fd5bd76310`. Cada búsqueda reutiliza la transcripción guardada. Podés pedir hasta cinco propuestas de 20 a 60 segundos. El sistema devuelve las coincidencias que encuentra.

1. Abrí un proyecto completado con transcripción y desplegá **Buscar momentos por tema**. Probá una idea reconocible del video. «Cómo reparar un freno» y «Ejemplos concretos para principiantes» son ejemplos generales.
2. Si querés, agregá instrucciones como «evitá la introducción». Indicá el máximo de propuestas y abrí **Revisar texto y destino**. Revisá la transcripción y los datos que se enviarán a OpenAI. Autorizá el envío y generá las propuestas.
3. Compará **Por qué coincide según la IA** con la evidencia de la transcripción. Usá **Reproducir intervalo** para ver ese momento en el original. El panel conserva el historial y permite recuperar búsquedas anteriores. Si el tema no tiene coincidencias suficientes, probá otro enfoque.
4. Abrí una propuesta como borrador. Ajustá el recorte, el texto, el estilo, el logo y el encuadre. Exportá y marcá esa versión para el ZIP desde su tarjeta.

La prueba con voz sintética cubrió todo el video de 20 minutos, incluida una propuesta entre 19:02 y 19:41. Las capturas muestran temas presentes, un tema ausente y el recorrido hasta el ZIP. [Búsquedas y capturas](https://github.com/AldemaroCruz/ClipForge/actions/runs/46116426162/artifacts/15252033378) · [Capturas y recibos del MP4 y el ZIP](https://github.com/AldemaroCruz/ClipForge/actions/runs/46120063759/artifacts/15253603462)

## Crear clip desde la transcripción

Disponible en INT en el commit `e7145844fd9db57df9a5ad20593c8df2da00080f`. Los proyectos nuevos preparan las marcas durante el procesamiento del video.

1. Abrí un proyecto completado y desplegá **Crear clip desde la transcripción**. Reproducí un pasaje desde su tiempo en la lista.
2. Seleccioná texto consecutivo con el mouse o marcá inicio y final con los controles de selección. Los controles también funcionan con teclado y en una pantalla estrecha. Revisá el inicio, el final y la duración visible. Los recortes pueden durar de 1 a 60 segundos.
3. En proyectos anteriores, podés usar los tiempos por segmento mientras pedís **Preparar marcas por palabra**. Si el transcriptor produce una versión diferente, podés abrir la alineación adicional. La transcripción original sigue disponible. En segmentos con marcas incompletas, la selección usa los límites de la frase.
4. Reproducí la selección y escuchá los bordes. El transcriptor estima los tiempos. Usá **Crear clip con esta selección** y ajustá los bordes con **Revisar inicio** y **Revisar final** en el editor.
5. Corregí los subtítulos, aplicá un estilo o logo y guardá el borrador. Exportá y descargá MP4, SRT y VTT desde su tarjeta. También podés incluir esa versión en el ZIP junto con otros clips.

La prueba en INT llevó un pasaje del minuto 18 de una lectura humana de 20 minutos hasta un MP4 con subtítulos y logo y un ZIP con los archivos exactos. Los recibos incluyen fragmentos del audio original y del MP4 para revisar los bordes. [Lectura de LibriVox](https://librivox.org/el-ingenioso-hidalgo-by-miguel-de-cervantes-saavedra/) · [Capturas, recibos y audio](https://github.com/AldemaroCruz/ClipForge/actions/runs/46153668496/artifacts/15267434009)

## Preparar textos para publicar

Disponible en INT desde el commit `352e0f7f8fdbe6622dd5d798c7c735f43cea6274` para clips automáticos, recortes manuales y exportaciones editoriales o creadas desde la transcripción.

1. En la tarjeta de un clip o exportación terminada, abrí **Preparar textos para publicar**. Escribí un título, una descripción o hashtags. Podés cambiar el idioma de los textos.
2. Si querés sugerencias, elegí el idioma y revisá el texto que se enviará al proveedor. Autorizá el envío, pedí las sugerencias y revisá que se ajusten al audio o a los subtítulos de esa variante. Elegí el título que quieras conservar y editá los campos.
3. Pulsá **Guardar para el paquete**. Podés copiar cada campo y descargar `publicacion.txt` con el título, la descripción y los hashtags de la revisión guardada.
4. Seleccioná el clip y sus textos en el ZIP. La carpeta de esa variante reúne el archivo de publicación en UTF-8 y los archivos multimedia disponibles. Una exportación con cambios de apariencia puede recuperar los textos cuando el contenido coincide.

En la prueba desde una cuenta normal, OpenAI sugirió «Agua de lluvia para el huerto» y «Cómo ajustar el freno de una bicicleta» para dos intervalos del mismo video. La edición manual persistió tras una respuesta tardía y al volver a iniciar sesión. El ZIP reunió cinco variantes y cuatro archivos `publicacion.txt`. Los MP4, SRT y VTT coincidieron byte por byte con sus descargas individuales. [Capturas y comprobaciones](https://github.com/AldemaroCruz/ClipForge/actions/runs/46159322368/artifacts/15270171551)

## Resaltar palabra actual

Disponible en INT desde el commit `51da59c5992a88be5114fb69171dedaf9da24eb9`.

En **Subtítulos**, activá **Resaltar palabra actual** y elegí el color base y el activo con el selector o el código HEX. Reproducí el recorte o mové el cabezal para comprobar el efecto. En una pausa del habla, el texto vuelve al color base.

Pulsá **Guardar como estilo** para conservar ambos colores y la opción de resaltado en tu biblioteca. Podés aplicar la plantilla a otro borrador. Los trabajos y estilos existentes empiezan con el resaltado apagado.

Si una frase editada ya no coincide con las marcas, se mantiene estática y el editor muestra un aviso. Para un trabajo anterior sin marcas, usá **Preparar marcas por palabra** cuando esté disponible. El texto corregido se conserva.

Exportá con **Incrustar subtítulos** habilitado para ver el efecto en el MP4. Los archivos SRT y VTT conservan su texto y sus tiempos. Podés seleccionar esta variante exacta en el ZIP y reutilizar los textos de publicación si el contenido sigue siendo el mismo.

La aceptación comprobó el primer y el último término, las repeticiones, las pausas y la posición del texto en el editor y el MP4. Podés abrir las capturas y comparar las exportaciones con y sin resaltado. Los WAV conservan el audio para revisar la sincronía de oído. [Evidencia de E01](https://github.com/AldemaroCruz/ClipForge/actions/runs/46167894270/artifacts/15273392326)

## Base de continuidad y reversión de logos

| Componente | Pin aceptado |
|---|---|
| Portal | Commit `cbfb913190f5893df371e8ba156ebc7976a2058a` |
| Frontend | `clipforge-int-beta-00058-zmf` |
| API | `clipforge-int-beta-api-00059-2jg` |
| Imagen de frontend, API y migrador | `sha256:5f12993b27e5b8977419b1027e5a1bb667dfe6abb6fedf6583ec598ac9b11378` |
| Worker | Generación `60` al verificar la base, fuente `1fdd3d61718e23e67fa4625690416c677a198722` |
| Imagen del worker | `sha256:2e419a975173295eeb1796cb0be3fd36f56cd4cad5920a5d7a8a4694ba546f3c` |
| Perfil | `fb0cd729d79fc049994f0f9c223f520f498af24e`, 4 vCPU y 4 GiB |
| IA | OpenAI, `gpt-6-luna`, 100 reservas por día UTC |

El despliegue comprueba los recibos nativos del portal y del perfil. Guarda los pines efectivos antes de una migración aditiva con el portal disponible. Si falla la aceptación, la reversión restituye los componentes identificados y conserva habilitado el acceso público. [Recibo C06](https://github.com/AldemaroCruz/ClipForge/actions/runs/46088385849/artifacts/15241015222) · [Recibo del perfil](https://github.com/AldemaroCruz/ClipForge/actions/runs/46092661387/artifacts/15241319365)
