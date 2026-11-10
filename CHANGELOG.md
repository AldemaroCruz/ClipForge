# v0.4.2 — 2026-10-30 — Operación local y recuperación

- Panel /ops, métricas aditivas por fase, contadores de uso reportado y minutos humanos idempotentes.
- Lease de filesystem entre API y mantenimiento offline; backup/verify/restore por CLI, hashes y mtime_ns preservados.
- Restore a carpeta nueva; nunca sobreescribe data/. Rutas desconocidas/enlaces rechazan, secretos reconocidos se excluyen.
- Captura dinámica del runtime instalado y del snapshot Whisper existente. Actualización FROM imagen conservada, sin pip/apt.
- Verificación de modelo fijado, aceptación read-only de entregas, scripts PowerShell de preparación/rollback/evidencia.
- Roadmap incluido y estado EN VALIDACIÓN: Docker Desktop, tres proyectos reales y CI/scan pendientes.
- Selector IA, contratos, consentimiento, render, edición, plantillas y entrega conservados; no llamadas nuevas ni nube.

# v0.4.1 — 22 de octubre de 2026

- Contrato `editorial-2-prevalidated-ranges`: catálogo exhaustivo de intervalos válidos
  calculado localmente; respuestas mediante `range_id` restringido por JSON Schema.
- Preflight sin red si no existen intervalos o hay más de 500; sin recortes silenciosos.
- Validación local mantiene duración, pertenencia al tramo y no solapamiento.
- Diagnósticos estructurales persistentes incluso cuando todas las propuestas fallan.
- Distingue respuesta JSON recibida y validación editorial; aviso honesto para fallos
  antiguos cuyo detalle no fue guardado. No reenvía consultas al abrir el historial.
- Sin cambios de modelo, claves, dependencias, Dockerfile, Compose, Whisper o render.
- 28 regresiones nuevas más adaptación explícita del contrato en tests anteriores.

# ClipForge — Historial de cambios

## v0.4.0 — 2026-10-22

- Selección editorial opcional sobre transcripciones existentes: adaptadores OpenAI
  Responses/Ollama Chat, sin SDK/dependencias nuevas, desactivados por defecto.
- Preview local del texto/destino, consentimiento explícito enlazado a fuente y
  configuración, una llamada limitada sin reintentos ni cambios silenciosos de proveedor.
- Validación estricta de IDs de segmentos y rangos; títulos/razones/criterios revisables,
  comparación con el selector heurístico original, historial persistente e idempotencia.
- Crear/recuperar borrador desde propuesta sin render ni Whisper; conserva ediciones,
  origen y archivos originales. Exportación posterior por el flujo existente.
- Cuota local conservadora UTC, límites de entrada/salida/respuesta, errores honestos,
  no reenvío automático tras reinicio. No es un control de gasto del proveedor.
- Nuevo compose.ai.yaml, .env.ai.example y GUIA-IA.md. No claves en el browser/ZIP.
- 261 pruebas (46 nuevas), regresiones de UI y flujo nuevo con servidor de modelo
  simulado explícito; render y API reales. Sin Docker ni inferencia real LLM/ASR aquí.

## v0.3.1 — 2026-10-22

- Plantillas locales inmutables de Presentation: guardar y aplicar sin cambiar cues/rangos.
- Posición inferior/centro/superior, margen, contorno/color y sombra validados.
- Defaults compatibles y render ASS real; nuevas pruebas offline de píxeles en MP4.
- Revisión separada de cada variante: pending/approved/rejected, título/notas y revisión optimista.
- Entregas ZIP solo de variantes elegidas/aprobadas, manifest y hashes, sin originales.
- Controles de tamaño/espacio, copias por bloques, staging atómico y revalidación de aprobación.
- Conflictos y archivos ilegibles fallan de forma explícita; no se omiten resultados seleccionados.
- Sin cambios en selector, Whisper, Compose ni requirements. Dockerfile agrega check_branding.
- No se implementan selección musical, intervalos, LLM, publicación ni cuentas multiusuario.

# v0.3.0 — 2026-10-21

- Biblioteca local con búsqueda, paginación, miniaturas y nombres de proyecto.
- Modo de carga manual sin Whisper; mantiene el modo automático anterior.
- Selecciones de 1–60 s, límites numéricos/deslizadores, marcar posición y deshacer un rango.
- Reubicación de subtítulos que conserva ediciones en el tramo común y respeta huecos/borrados.
- Borradores JSON independientes, guardado explícito, copias y protección por revisión ante conflictos.
- Exportación de snapshots guardados; originales y variantes anteriores preservados.
- Tests de unidad/API/render y navegador; ver TEST-REPORT.md para alcance real.
- Sin cambios en Dockerfile, Compose ni dependencias; sin migración destructiva de jobs.

# ClipForge — Cambios

## v0.2.1 — Tamaño y color de subtítulos

- Nuevos campos validados `subtitle_font_size` (24–120, entero, default 52) y
  `subtitle_color` (`#RRGGBB`, default blanco). Compatibles con jobs anteriores.
- Controles sincronizados deslizador/número y selector/hexadecimal en carga y editor.
- Muestra ampliada, vista vertical con estilo activo y botón Restablecer.
- Estilo persistido por variante y recuperado con Usar estos ajustes. Mismo estilo
  para todo el clip; no hay cambios a los MP4 previamente generados.
- Aplicación real mediante ASS/FFmpeg, conversión RGB a BGR y validación contra
  inyección de markup. SRT/WebVTT siguen siendo texto y tiempos sin estilo.
- Chequeo del build ampliado: colores rojo/azul/amarillo y diferencia de tamaño
  medidos en píxeles decodificados del MP4, no solo en la vista previa.
- Sin cambios en Dockerfile, Compose, requirements, Whisper o sus verificadores.


## v0.2.0 — Presentación y revisión local

- Encuadre `contain`, `blur` o `crop` fijo, con posición y zoom validados.
- Vista del original y propuesta 9:16 en Canvas; reproductores de resultados.
- Subtítulos relativos al clip: edición de texto/tiempos, SRT/WebVTT y ASS incrustado.
- Variantes aisladas por UUID, estados atómicos, borradores recuperables y pausa
  de trabajos interrumpidos al reiniciar.
- Edición de jobs de v0.1.4 desde input.mp4 y transcript.json; no repite Whisper
  ni sobrescribe los resultados anteriores.
- Nuevo chequeo obligatorio de render/subtítulos reales durante el build.
- requirements.txt y compose.yaml sin cambios. No nuevas integraciones externas.

## Historial anterior

# Changelog

## 0.1.4 — 2026-10-19

Validación de medios antes de cargar Whisper: nuevo estado `validating`, inspección
ffprobe con timeout, conteo de pistas, duración y mensajes/códigos de rechazo.
Los MP4 sin audio ya no llegan al decoder sin advertencia. Se distinguen audio
inexistente, entrada inválida, video corto y transcripción sin texto. Metadatos
y error_code quedan en job.json; las versiones anteriores siguen siendo legibles.
Los errores inesperados mantienen sus tracebacks, sin capturas genéricas de IndexError.

La UI muestra duración/pistas y cambia «Consultar / reintentar» por «Consultar
estado»: nunca ha reanudado jobs. El render usa el índice de video utilizable y
exige una pista de audio, sin map opcional. Se ignora texto ASR vacío al seleccionar.

Nuevas CLI: `app.media` (diagnóstico de archivo, solo lectura) y `app.check_media`
(seis fixtures FFmpeg/ffprobe, sin inferencia), esta última obligatoria en el build.
La CLI ASR existente también verifica audio antes de cargar el modelo, pero permite
archivos cortos o de solo audio para diagnóstico.

Sin cambios en requirements.txt, compose.yaml, caché, datos ni algoritmo de ranking.
Sin generación de voz ni análisis visual. No se afirma haber inspeccionado el MP4
original del usuario: solo se aportaron logs/captura, no los bytes del video.


## 0.1.3 — 2026-10-19

### Corregido

Pin explícito `av==18.1.0` para evitar PyAV 19, que retiró `metadata_errors` de
`av.open`. faster-whisper 1.1.1 todavía lo utiliza y solo declara `av>=11`.
Se conservan todos los pins previos, incluido requests. No se modifica el
pipeline ni los datos. No es un lock completo de dependencias transitivas.

### Verificación funcional

El checker obligatorio del build añade decodificación real de WAV y MP4/AAC,
remuestreo/downmix a mono 16 kHz y ejecución del Silero VAD incluido sobre silencio.
Las pruebas funcionales no necesitan pesos de Whisper ni leen videos del usuario.
Si falla una operación el checker devuelve 1 y el build se detiene.
La salud HTTP sigue siendo solo salud de la API.

Nuevo `python -m app.smoke_transcribe /data/ID/input.mp4` para diagnosticar una
transcripción real bajo petición explícita, consumiendo el generador completo,
sin modificar archivos de un job. Puede descargar pesos; no ejecutado en este
entorno. README y TEST-REPORT explican cómo distinguir pruebas de regresión con
mocks, chequeos funcionales del build y el end-to-end en Docker Desktop.

Versión 0.1.3 en UI y API. Compose, datos, caché, escritura atómica, hilos,
selección y renderizado sin cambios respecto a 0.1.2. Jobs fallidos no se reanudan.

## 0.1.2 — 2026-10-19

### Corregido

Se agrega `requests==2.34.2` como dependencia explícita. El log del usuario
confirma que faster-whisper 1.1.1 falla al importarlo, antes de transcribir.
Los cuatro pins originales se conservan; no se cambian versiones de Whisper
ni se realiza un downgrade de Hugging Face.

### Verificación del build

El Dockerfile ejecuta `python -m pip check` y `python -m app.check_runtime`.
El segundo comando verifica los imports reales de requests, Whisper y sus
principales bibliotecas, además de FFmpeg y ffprobe. Devuelve código distinto
de cero si falla. No descarga pesos, no llama a APIs ni procesa videos.
Se agregan pruebas unitarias para errores de imports, bibliotecas nativas,
binarios y códigos de salida. Leer TEST-REPORT.md para los resultados reales.

### Compatibilidad

Se conservan la escritura atómica, API, formato de estado, datos, caché,
configuración de Compose y único proceso Uvicorn de v0.1.1. La versión visible
pasa a 0.1.2. No se reanudan jobs fallidos: sube el video otra vez.


## 0.1.1 — 2026-10-19

### Corregido

Se reprodujo el error de v0.1.0 forzando una consulta entre el truncado y la
escritura de `job.json`: `GET /jobs/{id}` devolvió HTTP 500. `persist()` protegía
solo al escritor; el endpoint leía sin participar en ese lock.

Se centralizaron las escrituras de JSON con serialización previa, temporal en el
mismo directorio, flush, fsync y reemplazo. El estado usa snapshots independientes
para evitar mutaciones compartidas. Las lecturas tienen validación y reintentos
acotados; devuelven 503 si el archivo sigue dañado o inaccesible.

La UI ya no intenta interpretar un error HTTP como si fuese el estado del job.
Reintenta hasta cinco veces y después permite consultar manualmente o cargar de
nuevo el video. Los errores de FFmpeg incluyen un extracto del stderr. Los clips
parciales no se ofrecen para descarga. Se rechazan y limpian cargas vacías o que
exceden el tamaño permitido. Favicon devuelve 204 en lugar de 404.

### Mejoras locales

- Modelo cacheado en una carpeta montada persistente.
- Un job procesándose a la vez dentro de un solo proceso Uvicorn.
- API de salud con versión y healthcheck en Compose.
- Puerto del host vinculado a 127.0.0.1.
- Jobs interrumpidos por reinicio marcados como fallidos, sin borrar archivos.
- Pruebas de regresión, render sintético y comportamiento de la interfaz.

### Compatibilidad

Se conservan `/`, `/health`, `POST /jobs`, `GET /jobs/{id}` y la ruta de descarga,
y también el esquema básico de `job.json` y el montaje `./data:/data`.

No hay migración a base de datos, cambios de versiones en `requirements.txt`,
LLM, subtítulos, publicación automática ni garantía de uso en producción.
No se reconstruyen archivos JSON corruptos ni se reanudan trabajos interrumpidos.
