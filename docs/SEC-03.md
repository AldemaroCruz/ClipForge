# SEC-03: dos correcciones mínimas y preparación de Git

10 de noviembre de 2026, Guatemala. **SEC-02 terminó su alcance técnico local;
CI, release y despliegue siguen sin aprobar. Bandit y Trivy permanecen
bloqueantes; GitHub Actions real continúa pendiente.**

Se trabajó en `C:\Users\itres\Desktop\clipforge-mvp`. No se leyó contenido
operativo, caché/modelos, credenciales, videos o respaldos. Solo se inspeccionaron
montajes y comando del contenedor activo, sin entorno: no monta código ni usa
reload. No se detuvo, reconstruyó, reemplazó o actualizó ese servicio. La copia
de `source\repos` no se inspeccionó ni modificó.

## Las dos correcciones

1. `app/main.py`: se verificó que `subprocess` solo aparecía en el import y se
   retiró esa línea. No cambia lógica API, render o formatos. El test AST comprueba
   el retiro sin importar la aplicación en el host.
2. `scripts/capture_runtime.py`: `ffmpeg_version()` conserva
   `subprocess.check_output(['ffmpeg','-version'], text=True)`, con **timeout=10**.
   Rechaza explícitamente respuesta vacía, whitespace o primera línea vacía con
   `ValueError`. Conserva sin transformar `CalledProcessError` ante retorno no
   cero y `TimeoutExpired` al agotar el plazo. Devuelve la primera línea válida
   tal como antes. La captura no publica sus tres archivos si esta consulta falla.

La extracción de esa consulta permite probarla directamente; no renombra imports
o APIs para evitar Bandit. Sus B603/B607 continúan detectados en la línea 57.
El otro subprocess de pip permanece detectado; no se modificó su comportamiento.
No se cambiaron dependencias, locks, Dockerfiles, Compose, render, formatos,
workflow, validador, comando/umbrales de Bandit o scripts de despliegue.

## Pruebas nuevas y ejecución integrada

`tests/test_capture_runtime.py` añade **10 IDs**. Metadata de paquetes, modelo,
plataforma, reloj y pip son fixtures/mocks; jamás se ejecutó la captura contra
el servicio operativo o su caché. Se comprobaron:

- Versión válida y conservación exacta de su primera línea; llamada con timeout
  productivo de 10 segundos.
- Respuesta vacía y variantes de whitespace/primera línea vacía.
- Retorno no cero y timeout conservando sus excepciones; ningún output publicado.
- Proceso controlado real de Python como sustituto del comando: print, exit(7)
  y sleep. Solo el sleep de la fixture usa 0,1 s; la configuración productiva
  sigue siendo 10 s.
- Captura completa sobre datos enteramente sintéticos y contrato de entrada CLI
  ejecutando su bloque AST real bajo mocks. Esto no se presenta como captura
  operativa o inspección de un runtime real.

La candidata CI se construyó desde un contexto externo permitido de **87 archivos
/ 901413 bytes**, preparado y verificado antes del build. Imagen:
`clipforge/ci:sec03-e214edcb`, ID
`sha256:ed3d85ccdb4f48ce1fe1701fc775a613f156aa6918c4375bcb3355e5e2426f16`.
Los tests fueron sin red externa, claves, datos o montajes operativos, con raíz
readonly, capacidades eliminadas y temporal exclusivo. No se usó Compose ni
puertos del host.

| Control nuevo ejecutado | Resultado |
|---|---|
| Discovery y suite | **541 IDs únicos descubiertos y ejecutados**, sin fallos, errores, skips, expected failures o unexpected successes |
| Inventario | 531 anteriores preservados; 10 añadidos, cero retirados; IDs/hashes completos en `test-inventory-diff.json` |
| Checks del runner | 11 PASS, incluidos pip/runtime/VAD/decoder, media, presentación/branding real, inventario, completitud y cobertura |
| Cobertura | 3584/4366 líneas = **82,09%**; 1011/1410 ramas = **71,70%**; combinado 79,55%; cero exclusiones, sin umbral nuevo |
| Bandit 1.9.4 | **39 LOW** de confianza HIGH, cero errores; salida 1 bloqueante |
| SBOM de la imagen nueva | Generado con salida 0 y vinculado al ID probado |
| Trivy de la imagen nueva | **226 hallazgos / 52 CVE**, 1 CRITICAL y 225 HIGH; salida 1 bloqueante |
| Gitleaks 8.30.1 sobre la selección Git | Salida 0, cero hallazgos en las 127 rutas propuestas; lista explícita, no índice Git |
| Actionlint 1.7.12 | Nueva ejecución local, salida 0 sobre el workflow sin cambios |

Bandit baja de 40 a 39 únicamente por retirar B404 del import sin uso. Quedan
B404=12, B603=16, B607=11. El defecto de timeout/salida vacía se corrige, pero
no elimina automáticamente las alertas genéricas de subprocess. No hay nuevas
aceptaciones o exclusiones.

Trivy **0.76.2** se ejecutó sobre el TAR de esta imagen nueva, sin red, con la
base congelada de SEC-01/SEC-02: SHA-256
`da5b3caa6239084e8b921ca0aee661f127c1d18d86b55c6594fad5d2b8dc02b0`,
UpdatedAt `2026-11-10T01:02:55.861099573Z`. No se refrescó esa base, consultaron
todos los CVE o cambió el OS. Se conserva ese bloqueo por separado de SAST.

No se construyó ni probó otro navegador en SEC-03: los seis escenarios y el scan
browser de SEC-02 son históricos, no evidencia de esta imagen nueva. Tampoco se
ejecutó un expediente completo del workflow/validador real SEC-03; su código y
política están intactos y sus 40 tests permanentes pasaron en la suite nueva.
La cobertura no incorpora browser/JS ni subprocesses de los checks CLI. No hay
inferencia ASR/LLM real, aceptación editorial o despliegue.

## Propuesta SAST, todavía sin efecto

[SEC-03-SAST-policy.md](SEC-03-SAST-policy.md) reutiliza la clasificación de
SEC-02. Separa defectos concretos, evidencia insuficiente y usos revisados que
podrían plantear una decisión individual. Incluye una ficha candidata B603 de
`app/audio_check.py`, **pendiente/no aceptada**, con hashes de archivo/span,
justificación, controles, alcance exclusivo, responsables por designar y
condiciones de revisión/expiración/aprobación explícita. Cada otra ubicación
necesita ficha propia; no se aceptan reglas, imports o directorios completos.

## Referencia Git preparada

[SEC-03-Git.md](SEC-03-Git.md) registra `.git` ausente en el proyecto y los cuatro
ancestros hasta `C:\`, mediante metadatos dirigidos. No se enumeró el Escritorio
ni se incluyó un ancestro en la selección. No se ejecutaron `init`, `add`,
`commit`, `push` o `git config`; no se inventó autor/correo. La consulta local
`git --version` solo identifica la herramienta instalada.

La selección exacta propuesta para el primer commit contiene **127 archivos**,
sin globs: las 123 fuentes/configuración/documentación SEC-02 y los cuatro
archivos nuevos de SEC-03. Está en:

- `.ci-local/sec03-e214edcb/git/selection-paths.txt`: lista legible completa.
- `selection-paths.nul` del mismo directorio: mismas rutas ordenadas, UTF-8 sin
  BOM, con NUL final, para pathspecs literales.

Se excluyen datos, cache, backups, release, evidencias, restauraciones, `.ci-local`,
dotenv privados, Compose generado, credenciales, imágenes y estados Terraform.
Solo `.env.ai.example` está permitido como ejemplo. Antes de leer fuentes se
validan todos los nombres y componentes y se rechazan enlaces/reparse/hardlinks.
El scanner recibe un snapshot de esta selección, no el proyecto completo.

La selección pasó Gitleaks sin red; los informes reales y su manifiesto SHA256
están en `.ci-local/sec03-e214edcb/git/`. La pasada final incorpora este cierre
documental sin reemplazar la anterior. El resultado no garantiza por sí solo
que un archivo externo a la lista sea seguro ni autoriza un add global.

`.gitignore` permanece intacto. La revisión documenta brechas para dotenv con
otros nombres, extensiones de medios/archivos fuera de carpetas y claves. Son
ajustes propuestos para otra autorización; la selección literal y el scanner
siguen siendo obligatorios y no dependen de esos ignores. `git check-ignore`
queda pendiente hasta una inicialización autorizada.

Los comandos de inicialización exacta del proyecto, add de la lista literal,
revisión del índice y commit están **propuestos, no ejecutados**, en la guía Git.
Antes de cada paso hay que revalidar ubicación, selección congelada y autorización
específica. Identidad real pendiente; no se proponen remoto, autenticación o push.

## Entrega y límites

El expediente nuevo es `.ci-local/sec03-e214edcb/`: patch de las dos correcciones
y tests, lista Git, manifiestos/hashes, informes reales, comandos y resultados.
`code-review.patch` contiene exclusivamente las dos correcciones y su test nuevo;
`commands-and-results.md` registra comandos y salidas. `security-summary-final.json`
consolida resultados, límites y preservación; `source-changes-final.json` identifica
también las actualizaciones documentales.
Los documentos SEC-01/SEC-02 y sus artefactos conservados no se sobrescriben.
Las comprobaciones históricas se citan con su imagen/alcance y no se atribuyen
a código nuevo. Se mantiene pendiente la ejecución de Actions en GitHub y todas
las decisiones de seguridad sin resolver. Esta entrega no autoriza release.
