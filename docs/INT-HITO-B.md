# ClipForge INT · Beta por invitación

## Para creadores

Abre [ClipForge INT](https://clipforge-int-beta-816643438938.us-central1.run.app)
cuando el administrador te confirme la invitación. Inicia sesión con los datos
de tu cuenta ClipForge. En **Mi cuenta** puedes cambiar tu contraseña y cerrar
sesión.

1. Selecciona un MP4 con video H.264 y audio AAC. La beta admite hasta 100 MiB,
   entre 20 segundos y 3 minutos de duración y hasta 1920 píxeles por lado.
2. Pulsa **Subir y procesar**. La página muestra la carga y el estado del
   procesamiento por separado. Puedes volver al trabajo desde **Mis trabajos**
   al recargar o iniciar sesión de nuevo. La carga directa se reanuda tras
   cortes transitorios mientras la pestaña y el archivo sigan disponibles.
3. Reproduce los clips con sonido y pulsa **Descargar** en el que quieras
   guardar. La selección es heurística y usa el audio transcrito. Se generan
   clips verticales de hasta 60 segundos.
4. Usa **Enviar feedback** para reportar un error, sugerir una mejora o
   comentar la calidad. Puedes asociar un trabajo o un clip e indicar si
   el clip te resultó útil o publicable. La opción sigue visible si falla
   el proceso.

El piloto admite un trabajo activo por creador y cuatro trabajos activos en
total, incluidas las cargas vigentes. El worker procesa uno a la vez. Las
reservas caducan a las 24 horas y un fallo recuperable admite un reintento.
El piloto se centra en el flujo de MP4 a clips y feedback. El editor avanzado
y la publicación automática quedan fuera de esta interfaz.

## Administración

Entra con la cuenta administrativa existente y usa **Mi cuenta** para crear
una cuenta normal por creador. Comparte la contraseña inicial por un canal
privado. En la pantalla principal, **Feedback recibido** muestra categoría,
comentario, contexto permitido y versión. La vista de feedback no concede
acceso a los videos o clips de otras cuentas.

## Entrega y reversión

`int-hito-b.yml` realiza las validaciones y el despliegue en tres jobs. El
job protegido publica los digest de los OCI validados. El worker procesa
H.264/AAC con FFmpeg 9.1, compilado desde la fuente firmada y sin libxml2.
La decodificación restringida entrega PCM a Whisper. Los informes de Trivy
cubren paquetes que detecta en cada OCI. La procedencia y la lista de
bibliotecas del FFmpeg compilado quedan en la imagen del worker.

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
cuentas, la base privada y el bucket de INT. Para retirar la primera entrega,
se deshabilita el acceso público del frontend beta mediante el plan revisado
de `infra/gcp/int-beta` con `serve_public=false`. El Hito A sigue disponible
en su servicio con IAP. Para revertir una entrega posterior, restaura los
digest de la última entrega aceptada en los servicios beta y el job worker,
y aplica el plan del mismo módulo. Conserva la base, los objetos y las
migraciones. No ejecutes `terraform destroy` ni reviertas el esquema.

La entrega registra el commit, las revisiones, los digest y la prueba de
carga, procesamiento y persistencia en los artefactos de Actions. La guía
debe usarse para invitar creadores una vez que termine la aceptación remota.
