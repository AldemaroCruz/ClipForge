# SEC-02: revisión estática de subprocess

Revisión del 10 de noviembre de 2026, exclusivamente en `C:\Users\itres\Desktop\clipforge-mvp`. Este documento conserva las alertas y propone trabajo; no autoriza suprimirlas ni modifica código, configuración o umbrales.

## Evidencia y límites

La entrada es `.ci-local/sec01-06e7d342/iteration-4/bandit.json`, generado el `2026-11-10T03:35:27Z`, SHA256 `3a4a10f57e82fb0da6fa3cdf1e0547783a29d591ff3cb07d5b51af5bf3619b96`. Contiene 47 alertas LOW/HIGH confidence y cero errores. Esta revisión cubre **40 alertas en 29 ubicaciones**: B404 = 13 importaciones; B603 = 16 llamadas; B607 = 11 llamadas ya incluidas entre esas 16. Las siete B101 pertenecen al trabajo separado de QA. No son 40 vulnerabilidades independientes demostradas.

Se leyeron el reporte existente y las fuentes permitidas, con sus números de línea. Las 29 líneas marcadas siguen correspondiendo a importaciones/llamadas actuales al verificarlas el `2026-11-10T13:51:54Z`. También se siguieron los llamadores y los esquemas de entrada en código, sin importar ni ejecutar la aplicación. Las rutas `/app/app/...` y `/app/scripts/...` del reporte se traducen a `app/...` y `scripts/...` del checkout.

**Ejecutado en esta revisión:** lectura de JSON/código, agrupación y hashes; consulta de documentación oficial. **Simulado:** nada. **Pendiente:** nuevas ejecuciones de Bandit/tests, ataques de prueba, resolución y permisos reales de ejecutables, UID/GID, montajes y comportamiento efectivo de procesos. El coordinador informó Docker Desktop indisponible. No se inspeccionaron variables ni recursos de la instalación operativa y no se abrió ningún medio, respaldo, cache o credencial. GitHub Actions sigue pendiente de ejecución en GitHub.

Las clasificaciones siguientes son conclusiones estáticas, no un dictamen de explotación ni una aceptación de riesgo:

| Código | Clasificación | Significado y efecto sobre el gate |
| --- | --- | --- |
| D | Defecto concreto + corrección propuesta | El código muestra una omisión específica. Se indica si es disponibilidad o higiene; no se presume una explotación. Sigue bloqueado hasta un cambio autorizado y su validación. |
| P | Uso revisado que necesita política | El propósito y el origen inmediato de los argumentos son acotados, pero falta formalizar/verificar la confianza del ejecutable, entorno y privilegios. No equivale a aprobación ni falso positivo. |
| I | Evidencia insuficiente | Hay entradas de usuario/artefactos o límites de confianza cuya seguridad no puede concluirse con esta revisión. Se indica la evidencia faltante. Sigue bloqueado. |

## Cómo interpretar las reglas y los controles

B404 advierte por importar `subprocess`; no identifica una llamada vulnerable concreta. B603 requiere revisar entradas aun sin shell. B607 señala ejecutables con ruta parcial y su selección mediante `PATH`. Estas reglas no certifican por sí solas validación de argumentos, permisos ni procedencia del binario. Fuentes: [Bandit 1.9.4 B404](https://bandit.readthedocs.io/en/1.9.4/blacklists/blacklist_imports.html#b404-import-subprocess) y [plugins oficiales B603/B607, etiqueta 1.9.4](https://raw.githubusercontent.com/PyCQA/bandit/1.9.4/bandit/plugins/injection_shell.py).

Python recomienda rutas completas para ejecutables y `sys.executable` para relanzar el intérprete. Sin `env=`, el hijo hereda el entorno; proporcionar un diccionario reemplaza ese entorno, pero no hace seguros sus valores. `run(timeout=...)` termina y espera al hijo directo al expirar; `Popen.wait(timeout=...)` requiere limpieza explícita. Ninguna llamada revisada solicita cambio de usuario/grupos. Los argumentos son listas y no se activa `shell=True`; esto no valida la sintaxis propia de FFmpeg. En Windows, un `.bat`/`.cmd` resuelto puede introducir parsing de shell. Fuente: [Python 3.12 subprocess](https://docs.python.org/3.12/library/subprocess.html).

`shutil.which()` comprueba disponibilidad y resuelve usando `PATH`/`PATHEXT`; no acredita propietario ni directorios protegidos. Convertir su resultado en variable no soluciona esa confianza. Fuente: [Python 3.12 shutil.which](https://docs.python.org/3.12/library/shutil.html#shutil.which).

`-protocol_whitelist file,pipe` limita protocolos. **No constituye una jaula de rutas de archivos**: la documentación define una lista de protocolos y `file` accede a archivos. Esta es una inferencia sobre el alcance del control, no evidencia de lectura no autorizada en ClipForge. Fuente: [FFmpeg, documentación oficial de protocolos n7.1.2](https://raw.githubusercontent.com/FFmpeg/FFmpeg/n7.1.2/doc/protocols.texi). La página HTML oficial agotó el tiempo de consulta; se verificó esta fuente primaria versionada como alternativa.

Para evitar repetir supuestos, cada llamada indica los siguientes perfiles. Los campos desconocidos permanecen desconocidos:

| Perfil | PATH, entorno, cwd y permisos aplicables |
| --- | --- |
| E0 | No hay `env=` ni `cwd=` en esa llamada: hereda ambos del proceso que la invoca. No se leyó su contenido real. `ffmpeg`/`ffprobe` sin ruta usan búsqueda del sistema; no se verifica directorio, propietario, permisos o tipo nativo del ejecutable. |
| E1 | Igual que E0, pero primero usa `shutil.which()`. Puede producir una ruta completa, pero depende del `PATH` recibido y no verifica confianza del archivo/directorios. |
| E2 | Usa `sys.executable` en lugar de buscar `python` por nombre. No comprueba su propiedad/permisos; los módulos se resuelven con el entorno/rutas Python efectivos. La llamada de captura hereda entorno y cwd. |
| E3 | Runner de tests: intérprete `sys.executable`, `cwd=source_root`, entorno explícito creado desde una copia del entorno recibido más overrides de aislamiento. No es una allowlist de variables. `PATH` y las demás variables no reemplazadas se conservan. |
| E4 | Runner de browser: intérprete `sys.executable`, `cwd` de fuentes temporales copiadas, entorno explícito desde copia del recibido más overrides. `PATH` permanece heredado; `CHROMIUM_EXECUTABLE` viene del toolchain inspeccionado. |
| R0 | No hay reducción de identidad/permisos en el subprocess. El hijo tiene los permisos efectivos del padre; no se observaron UID/GID, ACL, umask, enlaces de componentes o directorios del entorno real. El directorio temporal acota destinos generados, pero no restringe por sí mismo todas las lecturas del hijo. |

El **contrato escrito de CI**, sin ejecución nueva, añade `--network none`, filesystem raíz `--read-only`, `--cap-drop ALL`, `no-new-privileges`, `/tmp` temporal y solo montaje de reportes ([workflow](../.github/workflows/ci.yml#L139), líneas 139–152 y 184–194). Browser incluye `--init`. Esto no es aislamiento de la instalación activa ni prueba de ejecución como no-root: `Dockerfile.ci` no declara `USER` y esos comandos no fijan `--user`. La identidad efectiva y permisos de la imagen deben medirse después. Chromium se inicia con `--no-sandbox` en `scripts/run_ci_browser.py:68–70`; su protección depende del contenedor y requiere una decisión explícita de política, sin confundirlo con los controles de `subprocess`.

## Las 16 ubicaciones de ejecución

### C01 — `app/acceptance.py:92` — B603 + B607 — I

- **Ejecutable/args:** `ffmpeg -nostdin -v error -protocol_whitelist file,pipe -i <disk> -map 0:v:0 -map 0:a:0 -f null -`. Decodifica una entrega; no genera un archivo de salida.
- **Origen:** CLI `--data`/`--project`, JSON/ZIP de artefactos guardados; `disk` se construye como `<root>/<job_id>/exports/<eid>/clip.mp4` ([fuente](../app/acceptance.py#L28), líneas 28–93). Job/export IDs están limitados a 32 hex, basename permitido, archivo directo no-symlink, tamaños y SHA256 concordantes antes de decodificar. Es integridad frente al manifiesto, no autenticidad de un manifiesto arbitrario ni garantía sobre cada ancestro.
- **PATH/entorno/permisos:** E0 + R0. Root viene del operador; no se verificó su procedencia/permisos ni enlaces de componentes. No hay sandbox por invocación.
- **Timeout/resultado:** 1800 s, stdout/stderr capturados; se rechaza returncode no cero. No hay límite explícito de bytes capturados ni memoria por proceso.
- **Pendiente/propuesta:** definir ejecutable absoluto confiable y alcance de lectura de una entrega; probar con artefactos sintéticos y un árbol nuevo, incluyendo ancestros enlazados y formato malicioso. No abrir entregas reales para demostrarlo. Falta evidencia para garantizar confinamiento de archivos; no se afirma que exista un exploit.

### C02 — `app/audio_check.py:47` — B603 — P

- **Ejecutable/args:** resultado de `which("ffmpeg")`; lavfi negro fijo + WAV, duración 1 s, libx264/AAC y MP4 destino ([fuente](../app/audio_check.py#L36), líneas 36–52).
- **Origen:** `check_audio_stack()` crea WAV de tono determinista y rutas `tone.wav`/`tone.mp4` en `TemporaryDirectory` nuevo, líneas 84–98. No se toma una cadena de comando del usuario en ese flujo; `make_test_mp4()` como función admite rutas de su llamador.
- **PATH/entorno/permisos:** E1 + R0; el fixture no acredita confianza del binario.
- **Timeout/controles:** 30 s, `-nostdin`, salida capturada; returncode y archivo no vacío obligatorios.
- **Política/propuesta:** mantener el flujo de fixture y definir directorio/binario confiable; verificar ese contrato y permisos en CI aislado. No sustituir `which` por otra variable solo para retirar B603.

### C03 — `app/check_branding.py:12` — B603 + B607 — P

- **Ejecutable/args:** `ffmpeg` por nombre; entradas lavfi negras y seno fijas, duración 2 s, libx264/AAC, `-y`, destino suministrado ([fuente](../app/check_branding.py#L11), líneas 11–16).
- **Origen:** el flujo `check_branding()` crea `source.mp4` en temporal nuevo, líneas 40–43; el helper público recibe `Path` del llamador. No hay contenido de usuario en ese flujo.
- **PATH/entorno/permisos:** E0 + R0; `-y` puede sobrescribir el destino si el helper se usa con otra ruta, por lo que su contrato debe permanecer limitado a fixtures nuevos.
- **Timeout/controles:** 30 s, `-nostdin`, `check=True`, captura. Propuesta: ejecutable confiable y contrato de destino temporal; regresión de generación real sin tocar datos de usuario.

### C04 — `app/check_branding.py:20` — B603 + B607 — P

- **Ejecutable/args:** `ffmpeg -ss 0.8 -i <path> -frames:v 1 -vf scale=270:480,format=rgb24 -f rawvideo -`, más flags fijos ([fuente](../app/check_branding.py#L19), líneas 19–34).
- **Origen:** clips generados por `render_clip()` bajo el temporal de branding, líneas 44–52; helper acepta ruta del llamador.
- **PATH/entorno/permisos:** E0 + R0. Aquí no se fija protocol whitelist; el uso revisado solo procesa outputs sintéticos del renderer.
- **Timeout/controles:** 30 s, `-nostdin`, `check=True`; exige exactamente 270×480×3 bytes después de capturar. No limita bytes antes de finalizar la captura. Propuesta: política de binario y entrada solo fixture; conservar controles de píxeles y probarlos por separado con QA.

### C05 — `app/check_media.py:33` — B603 — P

- **Ejecutable/args:** `args[0]` es el literal `ffmpeg` definido en línea 19; lavfi fijo para negro/seno/silencio, duración, codecs y destino ([fuente](../app/check_media.py#L16), líneas 16–33). La ausencia de B607 en esta forma indirecta del AST no acredita una resolución más segura.
- **Origen:** seis casos constantes de `check_media()` y nombres `.mp4` dentro de temporal nuevo, líneas 39–54; el helper también admite segundos/ruta de su llamador.
- **PATH/entorno/permisos:** E0 + R0; sobrescritura `-y` dentro del fixture.
- **Timeout/controles:** 30 s, `-nostdin`, `check=True`, captura. Propuesta: mismo contrato de binario/destino que C03; mantener casos con/sin audio, silencio, corto, audio-only e inválido. No hay evidencia de ejecución nueva.

### C06 — `app/check_presentation.py:15` — B603 + B607 — P

- **Ejecutable/args:** `ffmpeg` por nombre; testsrc2 y seno constantes, duración por parámetro, libx264/AAC y destino ([fuente](../app/check_presentation.py#L14), líneas 14–21).
- **Origen:** `check_presentation()` llama con defaults de 2 s y `source.mp4` en temporal nuevo, líneas 64–68; helper recibe ruta/duración del llamador.
- **PATH/entorno/permisos:** E0 + R0. `-y` requiere mantener el destino en ese temporal.
- **Timeout/controles:** 30 s, `-nostdin`, `check=True`, captura. Propuesta: procedencia del ejecutable y contrato de fixture; conservar la generación real con audio.

### C07 — `app/check_presentation.py:25` — B603 + B607 — P

- **Ejecutable/args:** `ffmpeg` con entrada `path`, frame en 0.8 s y crop fijo 880:400:100:1280, gris rawvideo a stdout ([fuente](../app/check_presentation.py#L24), líneas 24–29).
- **Origen:** `contain_clean.mp4` y `contain_captions.mp4` generados en el temporal del mismo check, líneas 91–97.
- **PATH/entorno/permisos:** E0 + R0; sin protocol whitelist explícita en esta llamada de fixture.
- **Timeout/controles:** 30 s, `-nostdin`, `check=True`, captura; el llamador compara longitud y delta de píxeles. Propuesta: binario confiable, entradas solo generadas, conservar verificación de píxeles. Captura en memoria sin tope previo explícito.

### C08 — `app/check_presentation.py:39` — B603 + B607 — P

- **Ejecutable/args:** `ffmpeg` con entrada `path`, un frame, crop 1080×480 y RGB24 rawvideo a stdout. Las dimensiones interpoladas son constantes locales ([fuente](../app/check_presentation.py#L32), líneas 32–58).
- **Origen:** cuatro clips de color/tamaño creados por el renderer en temporal; colores constantes se usan en comparación posterior, no como filtros recibidos del usuario, líneas 101–111.
- **PATH/entorno/permisos:** E0 + R0; misma limitación de protocolos/lecturas y captura que C07.
- **Timeout/controles:** 30 s, `-nostdin`, `check=True`; longitud exacta 1080×480×3 y métricas de color. Propuesta: política de fixture/binario sin reducir controles RGB.

### C09 — `app/check_presentation.py:83` — B603 + B607 — P

- **Ejecutable/args:** `ffmpeg -nostdin -v error -i <path> -f null -` ([fuente](../app/check_presentation.py#L69), líneas 69–90).
- **Origen:** nombres constantes de variantes contain/blur/crop generadas por el renderer en temporal. No hay argumento libre para shell o un filtro recibido de API en esta llamada.
- **PATH/entorno/permisos:** E0 + R0; sin protocol whitelist explícita en esta decodificación de fixtures.
- **Timeout/controles:** 30 s, `check=True`, captura; comprobación previa de dimensiones y codecs mediante probe, posterior SRT/VTT. Propuesta: binario confiable y contrato de inputs generados; conservar validación de decodificación completa.

### C10 — `app/check_runtime.py:67` — B603 — P

- **Ejecutable/args:** cada resultado de `which(name)`, con `name` fijo en `("ffmpeg", "ffprobe")`, y solo `-version` ([fuente](../app/check_runtime.py#L62), líneas 62–79).
- **Origen:** constantes del check, sin rutas ni contenido de usuario. `which()` evita falta de comando, pero no valida de dónde viene.
- **PATH/entorno/permisos:** E1 + R0. No hay `env=` restringido; comparte el entorno del checker.
- **Timeout/controles:** 10 s, `check=True`, captura; salida de versión no vacía obligatoria. Propuesta: registrar/verificar ejecutable bajo directorios de imagen confiables y permisos en ejecución futura; no aceptar solo que una versión esté impresa.

### C11 — `app/media.py:42` — B603 + B607 — I

- **Ejecutable/args:** `ffprobe -v error -protocol_whitelist file,pipe -show_entries <lista fija> -of json <path.resolve()>` ([fuente](../app/media.py#L34), líneas 34–67).
- **Origen:** CLI acepta un `Path`; aplicación usa `ROOT/<UUID>/input.mp4` proveniente de upload, y checks usan fixtures. `main.py:301–314` exige extensión `.mp4`, nombre de almacenamiento fijo y límite de bytes; no convierte el contenido en confiable. Esta función solo exige archivo existente/no vacío y resuelve la ruta; no rechaza symlinks ni acota la ruta a un root por sí misma.
- **PATH/entorno/permisos:** E0 + R0. Es desconocido qué otros archivos podría leer el proceso nativo con sus permisos efectivos. La whitelist de protocolos no contesta esa pregunta.
- **Timeout/controles:** 30 s; errores de binario/timeout/returncode y estructura JSON tratados explícitamente. Lista de campos fija; captura completa sin tope explícito por bytes.
- **Pendiente/propuesta:** medir y limitar privilegios/árbol accesible en entorno aislado, binario confiable, política de enlaces y contenedores admitidos. Probar referencias a archivos señuelo de un árbol sintético y casos válidos. No se afirma lectura arbitraria demostrada ni se cambia el demuxer sin regresiones.

### C12 — `app/render.py:14` — B603 + B607 — I

- **Ejecutable/args:** `ffmpeg -nostdin -hide_banner -loglevel error -y` más `map(str, args)` en `run_ffmpeg()` ([fuente](../app/render.py#L12), líneas 12–23). El helper es genérico; no valida por sí mismo una gramática de argumentos.
- **Origen vinculado:** `render_clip():58–85` construye argv: origen resuelto, protocolo file/pipe, inicio/duración numéricos, filtro construido internamente, índices validados, codecs constantes y destino temporal. Duración ≤60.001 s, cues validados, ASS generado y escapado; `Presentation` limita enums/números/colores, sin filtro libre de API ([esquema](../app/presentation.py#L6)). Texto de cues se escribe en ASS, no se interpola como comando de shell. `main.py:136–138` conserva un wrapper previo, no añadido por esta revisión, y llamadas en 217–220/478–480.
- **PATH/entorno/permisos:** E0 + R0. El input procede de upload/proyecto; outputs pasan por `TemporaryDirectory` dentro del destino y `os.replace`. Esto controla publicación, no demuestra un sandbox de lectura del decoder ni ausencia de enlaces en cada ancestro.
- **Timeout/controles:** 1800 s; error por timeout/binario/returncode, captura y fragmento final de stderr en error; no tope de captura total. Se comprueba MP4 no vacío antes de publicar MP4/SRT/VTT.
- **Pendiente/propuesta:** fijar confianza del ejecutable y contrato de argumentos/archivos de este helper, revisar permisos y parser nativo con fixtures. Conservar filtros, audio, sidecars y publicación atómica. No introducir otro wrapper para que Bandit deje de observar la llamada.

### C13 — `app/workspace.py:340` — B603 + B607 — I

- **Ejecutable/args:** `ffmpeg -nostdin -v error -y -protocol_whitelist file,pipe -i <source> -map 0:v:0 -frames:v 1 -vf scale=320:-2 -threads 1 <output>` ([fuente](../app/workspace.py#L323), líneas 323–348).
- **Origen:** endpoint de miniatura; `load_job()` valida UUID en `main.py:51–69`; source fijo `ROOT/job_id/input.mp4`. Se rechazan jobs activos y falta de archivo. Output nuevo `source.jpg` en temporal bajo previews; target de cache fijo y protegido por `THUMB_LOCK`.
- **PATH/entorno/permisos:** E0 + R0. No hay verificación de symlinks/ancestros en esta función; el lock es del proceso, no una política de permisos. `ROOT` y los bytes del upload no fueron inspeccionados.
- **Timeout/controles:** 15 s; returncode/output obligatorios; reemplazo final y HTTP 422 ante fallos. Captura sin límite explícito de bytes.
- **Pendiente/propuesta:** misma política de binario, entrada y confinamiento que C11/C12; tests aislados de miniatura válida/dañada, timeout y enlaces señuelo. No se concluye que el UUID permita traversal ni que la ruta sea segura frente a un escritor local sin medir permisos.

### C14 — `scripts/capture_runtime.py:60` — B603 — P

- **Ejecutable/args:** `[sys.executable, "-m", "pip", "check"]` ([fuente](../scripts/capture_runtime.py#L56), líneas 56–61), sin install ni resolución de dependencias solicitada por el comando.
- **Origen:** constantes; el script inventaría paquetes del intérprete activo. `--output`, `--cache`, `--model` no se pasan a este subprocess. El flujo posterior lee cache de modelo; **no se ejecutó ni se autoriza ejecutar este script contra la instalación operativa**.
- **PATH/entorno/permisos:** E2 + R0. La resolución de `pip` depende del intérprete y rutas/entorno Python heredados; se desconoce su contenido real.
- **Timeout/controles:** 60 s, captura, returncode no cero detiene la captura. Propuesta: definir un contexto explícito autorizado y limpio para usar esta herramienta; verificar intérprete/módulo y entorno con fixtures sin cache real. Este diagnóstico no requiere ejecutar una captura.

### C15 — `scripts/capture_runtime.py:65` — B603 + B607 — D

- **Ejecutable/args:** `subprocess.check_output(["ffmpeg", "-version"], text=True)`, después `.splitlines()[0]` ([fuente](../scripts/capture_runtime.py#L63), líneas 63–65).
- **Origen:** argumentos constantes; no procesa medios. La versión es texto entregado por el ejecutable seleccionado.
- **PATH/entorno/permisos:** E0 + R0; además de la dependencia de `PATH`, no hay timeout. Un comando que no termine puede bloquear la captura indefinidamente. Es una omisión de disponibilidad observable estáticamente, no evidencia de que el FFmpeg instalado sea malicioso o esté colgado.
- **Controles:** `check_output` exige returncode cero; salida capturada, sin validación explícita de lista no vacía antes de indexar ni tope de bytes.
- **Corrección mínima propuesta, sin aplicar:** timeout finito acorde con C10 (10 s), manejo explícito de salida vacía, ejecutable absoluto de procedencia verificada. Regresiones futuras con comando controlado que exceda timeout, versión vacía, error no cero y versión válida; sin ejecutar `capture()` ni abrir cache real. Mantener B404/B603 visibles después del cambio si siguen presentes.

### C16 — `scripts/run_ci_browser.py:90` — B603 — P

- **Ejecutable/args:** `[sys.executable, "-B", str(script)]`, `cwd=source`, `env=dict(environment)`, stdout/stderr en archivos nuevos exclusivos y sesión nueva ([fuente](../scripts/run_ci_browser.py#L86), líneas 86–109).
- **Origen:** seis nombres fijos en `SCENARIOS:25–32`; `run_browsers():143–171` copia solo fuentes/static directos a un temporal nuevo, rechaza symlinks de directorio/archivo y elige `workspace/tests/<filename>`. La función admite parámetros desde otros llamadores, pero el CLI usa este flujo acotado. No se revisó aquí todo subprocess interno de cada escenario ni la seguridad completa de copiar árboles concurrentemente modificables.
- **PATH/entorno/permisos:** E4 + R0. Overrides: datos/HF temporales, provider disabled, offline, bridge 0. El toolchain comprueba versión Chromium contra manifest y entrega ruta, pero usa `--no-sandbox`; no prueba permisos/propiedad del binario. La copia con `shutil.copyfile` no comprueba hardlinks/reparse Windows ni elimina la carrera entre comprobar y copiar; en CI requiere que el contexto verificado y la fuente permanezcan inmutables.
- **Timeout/controles:** llamador fija 300 s; `wait` al vencer envía SIGTERM al grupo POSIX, espera 5 s y SIGKILL/espera 5 s; rama Windows termina solo el proceso directo. La limpieza del grupo se hace al timeout, no tras todo exit normal/error; el contenido de los fixtures determina si quedan descendientes en esos casos. Resultados exigen exit cero, no timeout, PASS no vacío y sin marcadores de bridge.
- **Política/propuesta:** delimitar soporte Linux CI y ciclo de vida de descendientes; verificar finales normal/error/timeout y reportes, binarios y permisos con fixtures nuevos. No presentar la rama Windows como limpieza equivalente de un árbol ni asumir que el entorno copiado está libre de secretos. La red externa y montajes deben garantizarse fuera de esta función, conforme al workflow escrito.

## Las 13 importaciones B404 y sus usos vinculados

Una importación no recibe argv, PATH, entorno, permisos o timeout propios. Esos campos son **no aplicables al import** y quedan descritos para sus usos vinculados; cargar el módulo no lanza por sí solo un proceso. Todas siguen registradas como B404.

| Ubicación B404 | Uso real y clasificación | Acción propuesta o evidencia faltante |
| --- | --- | --- |
| `app/acceptance.py:13` | C01, I | Revisar confianza de binario/artefactos/confinamiento. Import necesario para ese uso. |
| `app/audio_check.py:12` | C02, P | Mantener fixture y decidir/verificar contrato del ejecutable. |
| `app/check_branding.py:3` | C03/C04, P | Mantener checks nativos; cambio B101 pertenece a QA y no resuelve automáticamente B404/B603. |
| `app/check_media.py:8` | C05, P | Uso necesario; `args` indirectos no eliminan el riesgo de PATH. |
| `app/check_presentation.py:6` | C06–C09, P | Decodificación y generación de fixtures; contrato de binario/entorno pendiente. |
| `app/check_runtime.py:13` | C10, P | Uso necesario para versión/errores; `which` no acredita procedencia. |
| `app/main.py:13` | D, importación sin uso en el archivo actual | `rg -n subprocess app/main.py` solo encontró esta línea. El wrapper previo de líneas 136–138 usa `run_ffmpeg` importado de render; no usa este import. Propuesta mínima: retirar únicamente el import no usado, con validación normal posterior. Es higiene, no una vulnerabilidad de ejecución demostrada. No se retiró en esta revisión. |
| `app/media.py:11` | C11 y `TimeoutExpired`, I | Import necesario; faltan límites de confianza de binario/archivos. |
| `app/render.py:3` | C12 y `TimeoutExpired`, I | Import necesario; no reemplazarlo por alias/import dinámico para evitar B404. |
| `app/workspace.py:12` | C13 y `TimeoutExpired`, I | Import necesario; evidencia de permisos y enlaces pendiente. |
| `scripts/capture_runtime.py:12` | C14 P + C15 D | Resolver omisión de timeout en C15 y política explícita del contexto de captura; el import no es el defecto de timeout. |
| `scripts/run_ci_browser.py:19` | C16 y `TimeoutExpired`, P | Import necesario; alcance de limpieza y contenedor deben verificarse. |
| `scripts/run_ci_tests.py:21` | P; `subprocess.run` como callable por defecto en línea 157 y `DEVNULL` en 228 | Uso vinculado detallado a continuación; no es import no usado. |

### Uso vinculado a `scripts/run_ci_tests.py:21`

`run_ci()` pasa `[sys.executable, "-B", "-m", *arguments]` al callable `command_runner` ([fuente](../scripts/run_ci_tests.py#L153), líneas 153–158 y 221–237). La lista constante `CHECK_COMMANDS:28–34` solo contiene `pip check` y cuatro módulos de checks. La ausencia de B603 en esta llamada indirecta es una limitación de identificación del scanner, no evidencia de menor riesgo. El callable inyectable permite tests; no debe usarse como wrapper para esconder subprocess.

Aplica E3 + R0. El runner primero informa si el provider recibido está disabled y el path de datos está bajo temporal; aun ante configuración incorrecta instala nuevos datos/HF temporales y overrides offline antes de importar app. `safe_environment:208–220` conserva el resto del entorno de entrada. El provider disabled y variables offline no sustituyen `--network none` ni impiden que una variable heredada contenga una clave. No se inspeccionaron variables reales. En un workflow sin secretos montados/inyectados, ese contrato debe comprobarse sin volcar valores.

Los timeouts son 60/180/180/240/240 s; `cwd=source_root`, stdout/stderr a DEVNULL, `check=False` y evaluación explícita del returncode. Se ejecutan checks y suite, y el resultado agregado conserva fallos. No hay cambio de identidad ni limpieza propia de grupos descendientes en `run_ci()`. Se necesita política verificable de imagen/entorno confiables y ejecución desechable; no quitar checks para eliminar subprocess. Regresiones futuras deben cubrir timeout, error del comando, entorno recibido incorrecto, argumentos fijos y propagación del fallo del check sin omitir la suite.

## Cambio mínimo y trabajos dependientes

1. **Cambios acotados proponibles, pendientes de autorización:** retirar el import sin uso de `app/main.py:13`; limitar C15 y validar versión no vacía. Son cambios distintos: el primero de higiene y el segundo de disponibilidad. La captura operativa continúa prohibida para validarlos; usar comandos/archivos nuevos sintéticos. Ninguno garantiza un Bandit verde.
2. **Trabajo de confianza del ejecutable:** definir ruta absoluta permitida y procedencia/permisos verificables para FFmpeg/ffprobe, con entorno explícito necesario y sin directorios escribibles/no confiables en la búsqueda. Mantener compatibilidad declarada Linux CI/Windows local; no hacer que el comportamiento dependa de un `which()` arbitrario ni usar `/usr/bin` en Windows. Medir UID/GID/ACL en una imagen CI propia cuando Docker vuelva. El alcance operativo requiere autorización aparte.
3. **Trabajo sobre medios de usuario:** C01/C11/C12/C13 necesitan un contrato de rutas/enlaces y del acceso que conserva el decoder. Evaluar restringir formatos si el producto promete solo MP4, límites de recursos/captura y proceso aislado; cualquier cambio de demuxer/parser o privilegios necesita PR separado con regresiones de MP4 reales sintéticos, audio, framing, filtros/ASS y errores. La extensión del upload y `file,pipe` no prueban este contrato.
4. **Trabajo de runners:** verificar protección del contexto copiado, entorno mínimo, fuentes inmutables y limpieza de descendientes en finales normales, errores y timeouts. La rama Windows de C16 no debe declararse validada por las pruebas Linux. Browser sin sandbox del navegador exige revisar los controles externos y sus límites. Coordinar con QA e infraestructura sin cambios encubiertos de política.

**Estado del control:** las 40 alertas revisadas siguen pendientes/bloqueantes bajo la política actual de todos los hallazgos. Esta clasificación no modifica Bandit, no autoriza `nosec`, exclusiones, baselines de supresión ni umbrales distintos. B404/B603 pueden continuar apareciendo tras corregir defectos concretos: una decisión de política no equivale a evidencia de ejecución ni cambia el scanner. Esta revisión no propone ocultarlos mediante aliases, wrappers o imports dinámicos.

## Huellas de las fuentes revisadas

Huellas SHA256 leídas durante esta revisión; identifican el texto examinado, no una captura de la instalación ni una ejecución. QA puede cambiar posteriormente `check_branding.py` en su trabajo asignado; el reporte original y estas huellas conservan el punto de comparación.

| Archivo | SHA256 |
| --- | --- |
| `app/acceptance.py` | `3b43768803b98377396c5b4c52a207eca87148a973ead1af8077d8512d91ec22` |
| `app/audio_check.py` | `bb21ca8546683c0b9bf1dc86e8bac18ce0f3436c4f20d771beb5f7e08bbb4c3a` |
| `app/check_branding.py` | `95a5f254dcfa6c1671950427017441fbf128f2806e59298b3ca47f7e67e9fc90` |
| `app/check_media.py` | `5593dc48b0b59b04e93d257044192066a02a177ace9aa58e3ba75dc810ff90de` |
| `app/check_presentation.py` | `6781621c296c203227bfa9ab837dd6429cdfac58bc6806958172f7d40532b3b3` |
| `app/check_runtime.py` | `ee23842fac7fd7c3a57012b6d1f7c4ee2305255b26a312568228b47b4906d2ae` |
| `app/main.py` | `c2badb0e1da592e9017b65e14cc0f0983e24049ddf878a939311cbfa6369c6a1` |
| `app/media.py` | `fa9edf248d47418951a5b96e917e0aa9a1bea47e208d07004ca8591088520ad1` |
| `app/render.py` | `1daa61b900d4684efaafc822d6d26633011cbdcd35172c0513d24581c7d54ff7` |
| `app/workspace.py` | `255b438ec80edd0a622a63714de40daac19946909702fd5116c88bc5260db3ea` |
| `scripts/capture_runtime.py` | `5cc5cac8cd7ab175266d1f54c5d4812f210500b5465ff2b41829f22cf87564aa` |
| `scripts/run_ci_browser.py` | `34c167bb03a93bf1232c4f04e7c726bb533bc3f4cb16697ca398707c9b3fdaa7` |
| `scripts/run_ci_tests.py` | `2bf0611742d5d4ab26e7146d6ec816702b306cac5e6cbdd835f06bfc17fd6a3a` |

Para reproducir la agrupación sin scanner ni ejecución de aplicación, leer solo el reporte autorizado con `ConvertFrom-Json`, filtrar `test_id` en `B404,B603,B607`, agrupar por `test_id` y por `filename:line_number`; después leer únicamente los archivos de código listados. No ejecutar `capture_runtime.py`, `acceptance.py` ni la aplicación para esta revisión.
