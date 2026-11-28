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
