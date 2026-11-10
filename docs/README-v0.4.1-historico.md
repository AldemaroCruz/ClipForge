# ClipForge AI v0.4.1 — Selección editorial asistida (beta)

FastAPI + faster-whisper + FFmpeg. Interfaz en español, sin cuentas. IA opcional
(OpenAI u Ollama), desactivada por defecto. Windows con Docker Desktop/WSL2, o Linux/macOS con Docker.
**Solo localhost. No es un servicio multiusuario ni está listo para exponerse a Internet.**


## Corrección de selección en v0.4.1

La versión 0.4.0 podía recibir JSON válido pero rechazar todos sus intervalos.
Además, el caso `AI_NO_VALID_CANDIDATES` perdía el detalle de cada descarte.
En 0.4.1 ClipForge construye localmente **todos los intervalos de segmentos completos**
que respetan el tramo y la duración elegidos. Envía el catálogo junto con la
transcripción. El modelo responde con `range_id` de un enum, título, motivo y
valoraciones; no inventa los extremos ni calcula la duración. La selección editorial
sigue siendo del modelo y debe revisarse: el catálogo no equivale a clips aprobados.

Máximo **500 intervalos elegibles por solicitud**, hasta 5 propuestas de salida.
Si el catálogo excede ese límite o el presupuesto de caracteres/contexto, la vista
previa lo rechaza antes de llamar al proveedor: reduce el tramo o estrecha las
duraciones. **No se muestrea, trunca ni divide silenciosamente la solicitud**.
El catálogo puede aumentar los tokens de entrada respecto a v0.4.0; se conserva
el límite previo de tamaño y se muestra la solicitud antes de consentir.
Si no existe ningún intervalo válido, tampoco se llama al modelo ni se reserva cuota.

La validación local conserva motivos individuales (ID desconocido, duración o
solapamiento) incluso si ninguna propuesta sirve. El panel distingue respuesta
JSON recibida de selección aceptada y permite leer un diagnóstico estructural.
No guarda cuerpos crudos del proveedor, claves ni entradas de error de Pydantic.
Los resultados aprobados sí conservan títulos/textos como antes.

Los análisis de **v0.4.0 permanecen intactos**. Si fallaron, no es posible reconstruir
la respuesta que esa versión no guardó. Abrir o actualizar su historial no envía
solicitudes. Después de actualizar prepara y autoriza un **análisis nuevo** con el
mismo proyecto; no hace falta subirlo ni transcribirlo otra vez. No hay retries ni
fallback de proveedor/heurística, y no se alteran clips, rangos, límites o modelo
para forzar un resultado. Un modelo puede devolver menos propuestas o ninguna.

### Actualizar una instalación que ya tiene IA habilitada

Conserva tu **`.env.ai` actual** y no pegues la API key en chats ni capturas. La
corrección no requiere cambiar modelo, clave ni límite de tokens.

```powershell
cd C:\Users\itres\Desktop\clipforge-mvp
# Detener solo cuando no haya un render o análisis en curso.
docker compose -f compose.yaml -f compose.ai.yaml down
# Copiar el contenido del ZIP encima del código. Conservar data/, cache/, .env y .env.ai.
docker compose -f compose.yaml -f compose.ai.yaml up --build -d --wait --wait-timeout 120
if ($LASTEXITCODE -ne 0) { throw "No se pudo construir o iniciar ClipForge" }
Invoke-RestMethod http://localhost:8080/health
Invoke-RestMethod http://localhost:8080/ai/config
```

Esperado: versión **0.4.1**, el mismo proveedor/modelo y configuración presente.
Estas consultas no realizan inferencia. Recarga con **Ctrl + F5**, abre tu proyecto
transcrito y prepara una nueva vista previa. Debe mostrar el número de intervalos
válidos antes de autorizar. Autoriza una sola vez, revisa propuestas y diagnóstico.
Un intento externo nuevo puede generar consumo; los fallos anteriores siguen
contando para la cuota local diaria (UTC).


## Arrancar / actualizar

Extrae el contenido de `clipforge-mvp` sobre la carpeta del proyecto. Conserva
`data/`, `cache/`, `.env` y `.env.ai`, si existen. Respalda cualquier cambio manual de código
antes de reemplazarlo. No crees `clipforge-mvp/clipforge-mvp`.

Desde PowerShell, en la carpeta que contiene `compose.yaml`:

```powershell
docker compose down
# Copiar aquí el código nuevo, conservando data/ y cache/.
docker compose up --build -d --wait --wait-timeout 120
if ($LASTEXITCODE -ne 0) { throw "Build o inicio fallido; revisa el primer error" }
Invoke-RestMethod http://localhost:8080/health
```

Esperado: `status: ok`, `version: 0.4.1`. Abre `http://localhost:8080` y recarga
con Ctrl + F5. Logs: `docker compose logs --tail 100 -f clipforge`.
Salir de los logs con Ctrl + C no detiene el servicio.

Compose base, Dockerfile, requirements.txt y las versiones fijadas de Whisper/PyAV
se conservan. Los chequeos nativos y de render no llaman al LLM. No se agregan Go,
React, Redis, PostgreSQL, cuentas de usuario ni facturación propia.
Un `health: ok` solo comprueba que la API responde, no una inferencia ASR.

## Novedades de v0.4.1

**Propuestas asistidas** trabaja sobre transcripciones existentes, sin repetir Whisper.
Elige un objetivo editorial y un tramo. Revisa exactamente qué texto se enviaría,
autoriza una sola consulta y compara los resultados con el selector original.
Los títulos, razones y criterios son sugerencias revisables; no predicciones de viralidad.
El servidor valida IDs de segmentos, intervalos y duración antes de aceptar propuestas.

**Crear / abrir borrador** guarda una selección sin renderizar. Repetir esa acción
recupera el mismo borrador, sin borrar sus cambios. La exportación conserva procedencia.
Los resultados van a `data/<job>/selections/<id>/selection.json`; no se reescribe el
original ni los clips anteriores. Consultar un análisis no vuelve a llamar al modelo.

Con el Compose base no se envía nada a un proveedor. La **comparación heurística
local** permite probar el recorrido sin claves ni IA. Para IA real debes configurar
`.env.ai` y el overlay opcional `compose.ai.yaml`. **Instalar esta versión no activa
consultas remotas automáticamente.**

Consulta [GUIA-IA.md](GUIA-IA.md) para activar OpenAI/Ollama, límites, privacidad y
la prueba de aceptación. Las pruebas incluidas usan respuestas de modelo controladas:
no son un benchmark de calidad editorial ni una prueba de inferencia real.

## Funciones conservadas de v0.3.1

### Plantillas visuales reutilizables

En la carga inicial y en el editor aparece **Plantillas reutilizables**. Ajusta el
encuadre, zoom, incrustación y estilo, escribe un nombre y pulsa **Guardar plantilla**.
La plantilla se guarda en `data/templates/<id>.json`. Para usarla en otro clip,
selecciona el nombre y pulsa **Aplicar**. Solo cambia ajustes visuales: no modifica
los textos corregidos, el rango ni los tiempos de subtítulos.

Las plantillas son copias independientes, no vínculos activos. No modifican MP4
ya generados ni se aplican a otros proyectos de forma automática. No hay edición
ni borrado de plantillas en esta versión: usa otro nombre para guardar una revisión.
Máximo local: 200. Nombres repetidos (sin distinguir mayúsculas) se rechazan.
Revisa siempre el encuadre: una posición de recorte útil en un video puede cortar
la cara de una persona en otro. Guardar plantilla NO guarda el borrador.

### Posición, margen, contorno y sombra

Además del tamaño/color de v0.2.1 puedes configurar:

- Posición: inferior, centro o superior.
- Margen vertical: entero 0–650, en coordenadas de la salida 1080 × 1920.
  Se mide desde el borde elegido; no se aplica a la posición central.
- Grosor del contorno: entero 0–12. Cero desactiva el contorno.
- Color del contorno: `#RRGGBB`.
- Sombra: entero 0–8. Cero la desactiva.

Los valores predeterminados mantienen el estilo anterior. SRT/VTT siguen siendo
texto y tiempos, sin estos estilos. Para ver los cambios en el MP4, activa
**Incrustar subtítulos** y genera una variante. La muestra/canvas es aproximada;
el MP4 exportado es la referencia de aprobación. No se incluyen fuentes nuevas,
fondos de texto, logos, nuevas tipografías ni animación palabra por palabra.

### Revisar cada variante, no el borrador

En **Variantes guardadas**, cada MP4 completado tiene un título de entrega, notas
para el cliente y estado **Pendiente**, **Aprobada** o **Descartada**. Pulsa
**Guardar revisión** explícitamente. Las notas se incluirán en el ZIP: no uses ese
campo para comentarios privados que no deban llegar al destinatario.

Todas las variantes existentes y nuevas empiezan pendientes cuando no tienen una
revisión guardada. La revisión se escribe en `exports/<id>/review.json`, sin
modificar `export.json` ni el MP4. Aprobar una variante no aprueba futuros renders
ni modifica el borrador. Un cambio en otra pestaña produce un conflicto y conserva
los valores actuales en pantalla. **Recargar revisión** pide confirmación para
descartar cambios no guardados y recuperar la versión almacenada.

Los clips automáticos iniciales no se incluyen directamente en las entregas:
ábrelos en el editor y genera una variante para revisarla. No se eliminan ni se
ocultan los originales. Esta aprobación es un control local de trabajo, no una
firma, una auditoría legal ni un sistema de permisos multiusuario.

### Crear el ZIP de entrega

Marca **Incluir en entrega** en las variantes aprobadas que quieras entregar y
pulsa **Preparar ZIP seleccionado**. El botón **Seleccionar aprobadas visibles**
marca como máximo 30 dentro de las 100 variantes recientes mostradas. El servidor
valida todas las revisiones y no crea un ZIP parcial si falta un archivo, se revocó
una aprobación o cambió su revisión. Máximo: 30 variantes / 2 GiB de archivos.

El ZIP se prepara en disco, sin volver a transcribir ni renderizar. Contiene:

```text
01_<id corto>/clip.mp4
01_<id corto>/clip.srt
01_<id corto>/clip.vtt     # cuando existe
manifest.json            # origen temporal, opciones y SHA-256 de los archivos
titulos-y-notas.txt       # título/notas por clip
LEEME.txt
```

No incluye `input.mp4`, transcripciones completas, otros proyectos, modelos o
archivos de plantillas. El original permanece en tu PC. Los MP4 se almacenan en el
ZIP sin recompresión de video. Se necesita espacio adicional equivalente al tamaño
de los archivos seleccionados, más un margen de 16 MiB.

Descarga desde **Paquetes preparados**. El ZIP y su registro se guardan bajo
`data/<job>/deliveries/<id>/`. Una entrega es una copia fija: cambiar un estado a
Descartada después NO elimina, modifica ni revoca ese ZIP, ni sus copias ya
compartidas. No hay envío ni publicación automática. No se borran entregas antiguas.

Solo se prepara un ZIP a la vez. La solicitud espera a la copia de archivos; si
pierdes conexión, consulta **Paquetes preparados** antes de reintentar para no
crear una copia adicional. La app permanece limitada a un proceso y localhost.

## Primera prueba de v0.3.1

Abre un clip existente y elige tamaño 72, color `#FFD54F`, posición inferior,
margen 230 y contorno negro de 5. Activa incrustación, guarda una plantilla con un
nombre nuevo y prueba Restablecer → Aplicar. Comprueba que no cambien texto ni
límites. Genera una variante, reprodúcela, apruébala y guarda la revisión. Marca
**Incluir en entrega**, prepara el ZIP y comprueba su MP4/SRT antes de compartir.
No hace falta repetir Whisper para probar esta versión.

## Funciones conservadas de v0.3.0

### Mis proyectos

La biblioteca encuentra los jobs existentes en `data/`, incluidos los creados por
v0.1.4/v0.2.x. Muestra miniatura, estado, duración disponible y cantidades de clips,
borradores y variantes. Permite buscar por nombre/ID, paginar y abrir sin copiar IDs.

Las nuevas cargas conservan el nombre del archivo y la fecha de carga. Los jobs
antiguos que no guardaban esos datos aparecen como `Proyecto <ID corto>` y muestran
**Fecha de archivo**, no una fecha de carga inventada. Usa **Renombrar proyecto**.
El nombre nuevo se escribe en `project.json`, no en el estado original.

La biblioteca se actualiza al abrir la página, consultar un proyecto, guardar o
exportar. **Actualizar** consulta cambios hechos en otra pestaña. No es un monitor
con actualizaciones en tiempo real para todos los jobs.

### Dos modos de carga

- **Automático:** valida, transcribe y propone hasta cinco ventanas de voz de
  20–60 segundos. Es el selector heurístico anterior; no predice viralidad.
- **Manual:** guarda y valida el original sin transcribir ni generar clips.
  Después pulsa **+ Clip manual**. Mínimo 1 segundo. Útil para elegir momentos
  a mano, incluido gameplay sin conversación. No detecta jugadas automáticamente.

Ambos modos requieren MP4 con pista de video y audio. El modo manual no exige voz,
pero esta versión todavía no exporta videos sin pista de audio. Máximo de carga
predeterminado: 300 MB. El primer uso del modo automático puede descargar el modelo
Whisper público; el modo manual no descarga modelos.

### Inicio y fin editables

**Editar clip** abre un fragmento existente. **+ Clip manual** permite comenzar en
cualquier parte del original, sin depender de los cinco fragmentos sugeridos.

Escribe inicio/fin en **segundos del original**, mueve los deslizadores o usa la
posición actual del reproductor. **Aplicar rango** actualiza el fragmento y sus
subtítulos. Guardar también aplica un rango pendiente, si es válido.

Límite de esta versión: **1–60 segundos por selección manual**, siempre dentro del
original. Es un límite del MVP, no una regla de las redes sociales. Son tiempos en
segundos, no edición por número de frame; la duración codificada puede diferir
aproximadamente un fotograma según la cadencia de entrada.

Los subtítulos siguen usando tiempos **relativos al inicio del clip**. Al cambiar
el rango, se conservan las correcciones en el tramo común, se recortan/descartan
los subtítulos fuera del nuevo intervalo y se añade texto de la transcripción solo
en las zonas nuevas. Las pausas y subtítulos eliminados dentro del rango anterior
no se rellenan de nuevo automáticamente.

**Revisa las frases en los bordes:** los subtítulos por segmento no permiten saber
qué palabras exactas sobrevivieron a un corte. Un subtítulo recortado conserva su
texto completo. No se inventan tiempos por palabra. El botón **Deshacer último
rango** recupera un solo estado anterior, incluido su texto; también revierte texto
editado después de ese ajuste. No es un historial ilimitado.

Sin transcripción guardada (o si es ilegible), se muestra un aviso. Puedes escribir
subtítulos o exportar sin incrustarlos. No se llama a Whisper al editar un proyecto.

### Borradores y exportación por separado

**Guardar borrador** persiste nombre, rango, encuadre, texto, tiempos y estilo en
JSON, sin generar otro MP4. Permite cerrar el editor, recargar o reiniciar la API y
retomar desde **Borradores**. No hay autoguardado; la interfaz avisa al salir con
cambios pendientes. Un borrador con “Incrustar” activo y sin texto puede guardarse,
pero no exportarse hasta agregar texto o desactivar la incrustación.

**Guardar copia** crea un borrador independiente. **Guardar y generar variante**
guarda primero y luego exporta una copia fija de esa revisión. Editar después el
borrador no cambia una exportación ya en cola o completada.

Cada actualización incrementa una revisión para detectar conflictos entre pestañas.
Una revisión desactualizada recibe HTTP 409 y no sobrescribe la guardada. La edición
actual permanece en pantalla y puede guardarse como copia. La revisión no implica
un historial recuperable de cada guardado: crea copias para conservar alternativas.

**Usar estos ajustes** sobre una variante abre una nueva copia sin guardar y conserva
sus propios límites. No vuelve accidentalmente al rango del clip original.

## Qué se conserva

El MP4 original, los clips iniciales, `transcript.json` y `job.json` no se modifican
al editar, guardar, renombrar o exportar. No se necesita migración masiva de datos.
Las exportaciones anteriores se mantienen. Es obligatorio conservar `input.mp4`
para volver a renderizar; la ausencia de original genera un aviso, no lo reconstruye.

```text
data/<job_id>/
  input.mp4
  job.json
  transcript.json              # solo si hubo transcripción
  clip_01.mp4                  # clips iniciales, cuando existen
  project.json                 # nombre personalizado opcional
  previews/source.jpg          # miniatura generada bajo demanda
  drafts/<draft_id>.json       # última revisión de cada borrador
  exports/<export_id>/
    export.json                # snapshot independiente + estado
    clip.mp4
    clip.srt
    clip.vtt
```

Los JSON nuevos usan escritura temporal y reemplazo, más un bloqueo por proceso.
No se truncan los originales. JSON ilegibles se conservan y se reportan; no se
regeneran silenciosamente. Los borradores sobreviven a reinicios, pero las tareas
de procesamiento/exportación interrumpidas **no se reanudan automáticamente**.
Genera otra variante desde el borrador si el render quedó interrumpido.

## Presentación conservada

Salida 1080×1920, H.264/AAC; imagen completa, fondo desenfocado o recorte fijo 9:16.
Tamaño de subtítulos 24–120, color #RRGGBB; mismo estilo por clip. Vista previa
aproximada, sin seguimiento de rostros. El tamaño/color se incrusta solo al renderizar
con la casilla correspondiente activa. SRT y WebVTT exportan texto/tiempos, no el
estilo visual. No se distribuyen fuentes tipográficas en este paquete.

## API nueva (local, sin autenticación)

| Ruta | Uso |
|---|---|
| `GET /projects?q=&offset=0&limit=12` | Biblioteca paginada |
| `PATCH /projects/{id}` | Cambiar nombre con `{"title":"..."}` |
| `GET /projects/{id}/thumbnail` | Miniatura JPEG local |
| `GET /jobs/{id}/workspace` | Duración real, fuente y disponibilidad de transcripción |
| `POST /jobs/{id}/editor/range` | Recálculo de rango/subtítulos, sin guardar ni renderizar |
| `GET /jobs/{id}/drafts?offset=0&limit=20` | Lista paginada de borradores |
| `POST /jobs/{id}/drafts` | Crear borrador |
| `GET /jobs/{id}/drafts/{draft_id}` | Recuperar borrador completo |
| `PUT /jobs/{id}/drafts/{draft_id}` | Actualizar con `revision` esperada |
| `POST /jobs/{id}/drafts/{draft_id}/exports` | Exportar `{"revision":N}` |

Se mantienen las rutas anteriores de clips y variantes. `POST /jobs` admite
`processing_mode=auto|manual` en multipart; el valor por defecto sigue siendo `auto`.
Documentación de esquemas: `http://localhost:8080/docs`.

## Pruebas

Desde la carpeta del proyecto:

```powershell
docker compose run --rm --no-deps clipforge sh -c "python -m pip install -r requirements-test.txt && python -m unittest discover -s tests -v"
```

Las pruebas generan material sintético en temporales. No uses `docker compose down
-v`, no borres `data/` y no reemplaces tus originales con fixtures. Los errores
inducidos por tests aparecen en logs: el resultado final de unittest es lo relevante.

Chequeos existentes:

```powershell
docker compose exec -T clipforge python -m app.check_runtime
docker compose exec -T clipforge python -m app.check_media
docker compose exec -T clipforge python -m app.check_presentation
docker compose exec -T clipforge python -m app.check_branding
```

El chequeo runtime valida imports, decodificación y VAD; no una transcripción completa.
Para ASR real en tu entorno, ejecuta lo siguiente fuera de otro procesamiento, con
un MP4 autorizado con voz (puede descargar pesos):

```powershell
docker compose exec -T clipforge python -m app.smoke_transcribe /data/ID_DEL_JOB/input.mp4
```

Pruebas de navegador opcionales: `tests/browser_smoke.py` (respuestas simuladas),
`tests/browser_workflow.py` (regresión de estilos/exportación) y
`tests/browser_editorial.py` (biblioteca, borradores, conflictos, cortes y reinicio),
y `tests/browser_delivery.py` (plantillas, revisión y ZIP real).
`tests/browser_ai.py` recorre preview → consentimiento → proveedor HTTP simulado
explícito → propuestas → borrador → render real. **No realiza inferencia real.**
Requieren Playwright/Chromium en la máquina de pruebas. Por defecto intentan HTTP
directo. `CLIPFORGE_BROWSER_BRIDGE=1` es un transporte explícito del harness para
entornos con navegación administrada: no prueba HTTP/Range nativo del navegador.
No debe usarse ese modo como evidencia de una sesión directa en Docker Desktop.

Consulta `TEST-REPORT.md` y `test-evidence/` para resultados reales y límites.

## Prueba editorial conservada

Abre el proyecto existente de unos 7 minutos. En `clip_01`, selecciona 310–345 s,
corrige una frase y guarda un borrador. Cierra y vuelve a abrirlo; confirma 35 s,
texto y estilo. Exporta y reproduce la variante. El clip inicial debe seguir intacto.
Después prueba **+ Clip manual** o una carga en modo manual con tu propio MP4.

## Límites y próximos pasos

Un proceso Uvicorn, archivos locales, sin base de datos, autenticación, usuarios,
cuotas comerciales, publicaciones ni selección visual automática. La IA opcional
tiene límites locales conservadores, no un control de gasto de una cuenta externa.
La biblioteca recorre archivos locales: no está optimizada para miles de proyectos.
Sin borrado desde UI, cancelación ni reintentos durables por etapa. Los hilos siguen
siendo el mecanismo del MVP. No mantengas varios contenedores sobre el mismo `data/`.

Las dependencias transitivas todavía no están bloqueadas por completo. No se ha
hecho un escaneo de vulnerabilidades ni una prueba de carga de esta entrega. Para
conservar un diagnóstico del entorno que te funcione puedes guardar, desde PowerShell:

```powershell
docker compose exec -T clipforge python -m pip freeze --all | Set-Content -Encoding utf8 runtime-installed.txt
```

Esto es un inventario de lo instalado, **no un lock verificado con hashes ni una
garantía de reproducción del sistema operativo/base de Docker**. Antes de ampliar
dependencias conviene validar transcripción real y reproducibilidad de la imagen.

## API añadida en v0.3.1

`GET/POST /templates`, `GET /templates/{id}`;
`GET/PUT /jobs/{job_id}/exports/{export_id}/review`;
`GET/POST /jobs/{job_id}/deliveries`,
`GET /jobs/{job_id}/deliveries/{delivery_id}/file`.

POST de entrega recibe `selections: [{export_id, review_revision}]`; no rutas
arbitrarias. GET de exports ahora incluye `review`. Los detalles completos del
esquema están en `http://localhost:8080/docs` mientras la app esté levantada.

## API añadida en v0.4.1

`GET /ai/config`, `GET /jobs/{id}/selections/context`;
`POST /jobs/{id}/selections/preview`, `POST /jobs/{id}/selections`;
`GET /jobs/{id}/selections`, `GET /jobs/{id}/selections/{run}`;
`POST /jobs/{id}/selections/{run}/candidates/{candidate}/draft`.

La creación de análisis exige `preview_token`, `request_id` y `consent:true`, además
de los mismos parámetros de la vista previa. No recibe URL ni clave desde el cliente.
Proyectos existentes sin transcripción conservan su edición manual. Sigue siendo
un MVP local sin autenticación, no debe exponerse a Internet.
