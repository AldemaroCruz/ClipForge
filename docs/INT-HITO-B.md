# ClipForge INT · Beta por invitación

## Para creadores

Abre [ClipForge INT](https://clipforge-int-beta-816643438938.us-central1.run.app)
cuando el administrador te confirme la invitación. Inicia sesión con los datos
de tu cuenta ClipForge. En **Mi cuenta** puedes cambiar tu contraseña y cerrar
sesión.

1. Selecciona un MP4 con video H.264 y audio AAC. La beta admite hasta 300 MiB,
   entre 20 segundos y 20 minutos de duración y hasta 1920 píxeles por lado.
2. Pulsa **Subir y procesar**. La página muestra la carga y el estado del
   procesamiento por separado. Puedes volver al trabajo desde **Mis trabajos**
   al recargar o iniciar sesión de nuevo. La carga directa se reanuda tras
   cortes transitorios mientras la pestaña y el archivo sigan disponibles.
3. Reproduce los clips con sonido y pulsa **Descargar** en el que quieras
   guardar. La selección es heurística y usa el audio transcrito. Se generan
   clips verticales de hasta 60 segundos.
4. En **Elegir fragmento del original** puedes revisar el video privado,
   elegir un intervalo de hasta 60 segundos y exportar un clip manual.
   También puedes abrir el recorte como borrador para editar y subtitular.
   Para un fallo recuperable, usa **Reintentar clip manual** sobre el mismo fragmento.
5. En **Propuestas por IA y edición**, escribe un objetivo editorial cuando
   el proveedor esté configurado. Revisa el texto, el destino y los rangos.
   Marca la autorización y pulsa **Solicitar propuestas**. El proveedor recibe
   la transcripción, los rangos y el objetivo. El video y el audio se procesan
   dentro de INT. Abre un borrador a partir de la propuesta elegida.
6. En el borrador, aplica el recorte y ajusta los tiempos o el texto de los
   subtítulos. Para incrustarlos en el MP4, activa la casilla y elige tamaño
   entre 24 y 120 y color. Los valores iniciales son 52 y blanco. Guarda y
   pulsa **Aprobar y exportar**. Cada revisión aprobada conserva su propio MP4,
   SRT y WebVTT, con subtítulos relativos al comienzo del recorte.

El piloto admite un trabajo activo por creador y cuatro trabajos activos en
total, incluidas las cargas vigentes. Hasta tres trabajos pueden procesarse a la vez. Las
reservas caducan a las 24 horas y un fallo recuperable admite un reintento.
Envía tus comentarios por escrito fuera de ClipForge.

## Subtítulos de clips automáticos

Al subir un video, **Generar clips con subtítulos incrustados** está activado.
Cada clip con voz muestra su MP4 y las descargas SRT y WebVTT con tiempos
relativos al intervalo. La opción de carga permite obtener el MP4 sin texto
incrustado. Los archivos de subtítulos siguen disponibles cuando hay voz.
Si el procesado detecta silencio o voz no transcribible, muestra ese estado.

Usa **Editar subtítulos** en un clip generado para modificar texto, tiempos,
tamaño, color, posición y contorno. El clip anterior se conserva como
**MP4 inicial** cuando una variante guardada está disponible. La vista previa
reproduce el propio MP4 de la variante. **Aplicar a todos los clips** cambia
el estilo base y reemplaza los estilos individuales, conservando los textos
y tiempos de cada clip. Los borradores nuevos de propuestas de IA heredan
el estilo del proyecto. Las exportaciones ya aprobadas conservan su versión.

El editor puede regenerar un clip anterior desde su original y transcripción
guardados. El cambio de estilo o texto genera únicamente las variantes
afectadas. Las vistas del clip muestran el estado de la última versión
solicitada, aunque una versión anterior termine después.

## Eliminación de proyectos

Abre el proyecto en **Mis trabajos**, pulsa **Eliminar proyecto** y verifica
el título y alcance en la confirmación. Al quedar registrada la orden, el
proyecto desaparece de **Mis trabajos**, se cierra su detalle y aparece
**Proyecto eliminado de tu cuenta**. La eliminación también se refleja al
volver a iniciar sesión. El enlace anterior deja de dar acceso al proyecto
y a sus archivos.

La cancelación y la limpieza de las generaciones accesibles se inician al
registrar la orden. PostgreSQL conserva el seguimiento de las generaciones
retenidas y la fecha informada por GCS. El bucket de INT aplica retención
mínima de siete días desde la creación de cada objeto y, al eliminar una
generación, permite recuperarla durante siete días más. Las esperas dependen
de cada objeto y quedan fuera de la interfaz. [Retención](https://docs.cloud.google.com/storage/docs/bucket-lock) · [Borrado recuperable](https://docs.cloud.google.com/storage/docs/soft-delete)

El reconciliador se despierta tras confirmar la eliminación. El job
`clipforge-int-project-cleanups` de Cloud Scheduler también llama cada minuto
a `POST /internal/project-cleanup` en `clipforge-int-beta-api`, autenticado por
OIDC con la cuenta invocadora del frontend. El reconciliador despierta el
worker existente sólo si hay una limpieza lista. Esto cubre reintentos y
recuperación después de interrupciones aunque el creador cierre el navegador.
[Invocación programada de Cloud Run](https://docs.cloud.google.com/run/docs/triggering/using-scheduler)

## Administración

Entra con la cuenta administrativa existente y usa **Mi cuenta** para crear
una cuenta normal por creador. Comparte la contraseña inicial por un canal
privado.

## Configuración de IA en INT

Activa el adaptador de OpenAI con una credencial del proyecto autorizado
para Responses API y un modelo con salida estructurada JSON Schema.
Agrega una versión en Secret Manager de `clipforgebeta2` con el nombre
`clipforge-int-openai-key`. Otorga `roles/secretmanager.secretAccessor`
sólo sobre ese secreto al servicio
`clipforge-worker-int@clipforgebeta2.iam.gserviceaccount.com`.
En el environment protegido `int` del repositorio configura
`INT_EDITORIAL_OPENAI_MODEL` con el identificador del modelo e
`INT_EDITORIAL_OPENAI_KEY_VERSION` con el número de versión del secreto.
El workflow monta la credencial en el worker y ejecuta la aceptación con
OpenAI cuando ambas referencias están presentes. El frontend y la API
usan únicamente la configuración pública del proveedor.

Con ambas variables ausentes, la interfaz muestra que falta configurar la IA.
La aceptación comprueba en ese perfil los borradores y archivos subtitulados,
y registra las comprobaciones del proveedor real como pendientes.

## Entrega y reversión

`int-hito-b.yml` realiza las validaciones y el despliegue en tres jobs. El
job protegido publica los digest de los OCI validados. El worker procesa
H.264/AAC con FFmpeg 9.1, compilado desde la fuente firmada y sin libxml2.
La decodificación restringida entrega PCM a Whisper. Los informes de Trivy
cubren paquetes que detecta en cada OCI. La procedencia y la lista de
bibliotecas del FFmpeg compilado quedan en la imagen del worker.

Los subtítulos se renderizan con la fuente DejaVu y libass 0.17.5, compilada
desde una release firmada. La compilación registra la revisión aplicada para
`CVE-2026-95127` y conserva la evidencia del código fuente compilado.
La aplicación genera el ASS con geometría fija, opciones validadas y texto
escapado. [Release libass 0.17.5](https://github.com/libass/libass/releases/tag/0.17.5)
[Cambio referenciado por Ubuntu](https://github.com/libass/libass/commit/d570c2f5ed55844ec9b77b085deb3cb8ef59cb4a)

La revisión del worker conserva `CVE-2025-25467` con la prioridad MEDIUM
que reporta Trivy para `libx264-164` en Ubuntu Noble. La biblioteca se usa
como codificador de fotogramas H.264 con parámetros del servidor. El
decodificador AAC de FFmpeg recibe el audio, y cada render se ejecuta en
un proceso acotado. Debian considera bajo el impacto en procesos de vida
corta. El hallazgo sigue abierto en el informe. [Ubuntu](https://ubuntu.com/security/CVE-2025-25467)
[Debian](https://security-tracker.debian.org/tracker/CVE-2025-25467)

La API acepta sólo la identidad de servicio del frontend a través de IAM.
El original viaja desde el navegador a Cloud Storage mediante una sesión
reanudable creada para el objeto y origen autorizados. El servidor valida
la propiedad y confirma tamaño y generación del objeto antes de encolarlo.
El worker valida códecs, duración y resolución antes de transcribir.

La migración de la beta tiene su propio registro aditivo y comparte las
cuentas, la base privada y el bucket de INT. Las migraciones aplicadas
conservan los comentarios históricos en PostgreSQL. Para retirar la primera
entrega, se deshabilita el acceso público del frontend beta mediante el plan revisado
de `infra/gcp/int-beta` con `serve_public=false`. El Hito A sigue disponible
en su servicio con IAP. Para revertir una entrega posterior, restaura los
digest de la última entrega aceptada en los servicios beta y el job worker,
y aplica el plan del mismo módulo. El workflow restaura las revisiones activas
y el digest del worker anterior si falla la aceptación. Conserva la base, los objetos y las
migraciones. No ejecutes `terraform destroy` ni reviertas el esquema.

La entrega registra el commit, las revisiones, los digest y la prueba de
carga, procesamiento y persistencia en los artefactos de Actions. La guía
debe usarse para invitar creadores una vez que termine la aceptación remota.
