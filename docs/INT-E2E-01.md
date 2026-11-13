# INT-E2E-01: aceptación integrada

Esta prueba local usa la imagen runtime candidata para API, migración y worker,
PostgreSQL exclusivo y el emulador [fake-gcs-server 1.56.1](https://github.com/fsouza/fake-gcs-server/releases/tag/v1.56.1).
No valida Cloud Run, Jobs en GCP, IAM de GCS, IAP ni la futura VM. No se ejecutó
apply o deploy, ni se aceptaron hallazgos de seguridad.

El lanzador `scripts/run_int_e2e.py` exige imágenes por ID/digest, un MP4 sintético
preparado fuera del checkout y UID:GID explícitos. Crea una red Docker interna
sin puertos host; comprueba ausencia de ruta por defecto y salida TCP. La
preparación de imágenes, pesos y voz ocurre aparte. No monta la raíz del proyecto,
usa datos del propietario ni comparte recursos con la instalación operativa.
El navegador es una herramienta de prueba distinta de la imagen runtime.

La aceptación comprueba login y CSRF reales, dos usuarios y rechazo cruzado,
upload con outbox/idempotencia, Whisper tiny multilingual real y offline,
selección heurística y manual, borrador con revisión, encuadre/subtítulos, render
FFmpeg, reproducción y descarga con Range. Sustituye dos veces el contenedor API
con caché vacía conservando PostgreSQL y objetos. También comprueba dos workers
competidores con máximo global de uno, renovación de lease, interrupción real
por SIGKILL, fencing y nueva variante explícita, recuperación y revocación de
sesiones. No modifica leases o estados para acelerar el caso de interrupción.

Los reportes públicos son `summary.json`, `browser-summary.json`,
`cloud-dispatch-summary.json` y `worker-child-termination-summary.json`:
resultados, contadores e identificadores de imágenes/modelo/fixture.
El inventario independiente y su contraste quedan en
`runtime-inventory/runtime-v4-independent-inventory.json` y
`runtime-v4-independent-comparison.json`, fuera del checkout. Incluyen paquetes,
rutas/hashes de binarios y pruebas de identidad; no contienen configuración de
sesión, credenciales o atributos de proyectos.
Contraseñas sintéticas, controles y logs permanecen en
`private/` fuera del checkout. No se generan HAR, trazas, screenshots, dumps de
base de datos ni archivos de sesión para publicar. La limpieza se ejecuta ante
fallo y sólo elimina nombres creados por el intento con ambas etiquetas de
propiedad coincidentes; nunca limpia Docker globalmente.

La aceptación local v4 pasó los **20 pasos** el 2026-11-13: 10 cues desde Whisper,
MP4 renderizado de 8.892.559 bytes, reproducción/descarga, API sustituida dos
veces, máximo activo observado de uno y lease renovada, interrupción recuperada
con fencing, nueva variante y recuperación de cuentas. La limpieza terminó con
cero contenedores y redes propios. La suite completa del contexto curado local
pasó **886/886**, sin errores ni skips, y sus checks nativos pasaron. También
pasaron los seis escenarios browser anteriores, AUTH y recuperación con PostgreSQL
de CI exclusivo. Los selectores e inventarios incluyen explícitamente `app/cloud`.
Se conservan
las regresiones unitarias con mocks como tales. Los dos contratos con PostgreSQL
real y llamada a Jobs simulada se ejecutan
obligatoriamente por `tests/cloud_dispatch_contract.py` desde el harness, fuera
del discovery de unit tests. Estos últimos usan
timestamps de fixture en schemas exclusivos; el caso SIGKILL del browser espera
la lease nativa de 60 segundos sin editarla. Whisper real y offline reconoció
**4/5 palabras** controladas en el recorrido v4 (mínimo requerido: tres); no se
publica la transcripción.

El caso nuevo termina sólo el Python `--execute` durante un render real: FFmpeg
deja de estar activo en menos de un segundo mientras PID 1 y el contenedor siguen
vivos, y el siguiente export del mismo supervisor termina. No se atribuye el
resultado a matar el contenedor. Se observó un zombie transitorio, sin actividad
multimedia, declarado en el reporte; no se afirma reap instantáneo. Cinco
regresiones del probe rechazan reutilización de PID, FFmpeg sobreviviente y
salida del contenedor como falsos positivos.

Identidades del intento válido `c063e69379654ab2`:

| Componente | Identidad |
| --- | --- |
| Runtime API/worker/migración | `sha256:7ef5a28a3fd02b73e1b6b90ba0e7a0be7c0f342dcc7d116bd6a081d58723b107` |
| Navegador de prueba | `sha256:3d3e08340b45503fef631ee6d3fe2c4bf304f2910b592fecef1625f788b4f4c5` |
| PostgreSQL de prueba | `postgres:18.7-trixie@sha256:9f4fd4aa918f52ae3d6f3b687f1de90d8f867cd4d520021545a9a50c120eae3b` |
| Whisper tiny multilingual | `Systran/faster-whisper-tiny`, revisión `d90ca5fe260221311c53c58e660288d3deb8d356`; archivos verificados en runtime |
| Video sintético | SHA-256 `8bad87d708e5ed14d27990ad10d8ef5b2d0fd6250c728e790dea85350997aa6c` |

El inventario independiente del runtime, capturado sin red ni credenciales,
coincide exactamente por nombre y versión completa con el SBOM/SCA OCI existente.
Quince regresiones validan ese contraste, incluidas identidades, listas completas,
épocas/revisiones Debian y diferencias de configuración; no sólo los contadores.

| Runtime v4, reporte Trivy 0.76.2 existente | Paquetes | CRITICAL | HIGH |
| --- | ---: | ---: | ---: |
| Debian 13.7 | 292 | 1 | 281 |
| Python 3.12.16, metadata de distribuciones | 46 | 0 | 0 |

Son los hallazgos reportados bajo los filtros de la ejecución original; no se
infiere ausencia de otras severidades. Node no está presente en este runtime.
Se registraron además **143 ELF** de wheels, **52 bibliotecas vendorizadas**,
todos con distribución propietaria y rutas/tamaños/SHA-256 en el inventario.
`av.library_versions` del wheel `av 18.1.0` registra libavcodec **62.28.102**,
libavformat **62.12.102**, libavutil **60.26.102**, libavdevice **62.3.102**,
libavfilter **11.14.102**, libswresample **6.3.102** y libswscale **9.5.102**.
Estos binarios son distintos de FFmpeg Debian `7:7.1.5-0+deb13u1`. El resultado
Python 0/0 no acredita cobertura SCA específica de las bibliotecas incluidas en
wheels. No se les atribuyen automáticamente los CVE de Debian, ni se extrapolan
estos resultados al navegador de pruebas, PostgreSQL o la futura VM.

El OCI escaneado tiene manifest
`sha256:d4b65631b30c26785ae18898cd826990fa20b4dce45015fb241ba108ddba7d49`
y config `sha256:3a4f5aa912fe8f12ca1ff67b9c7aa4391b9f23643b17872cf21da1a06659ee9f`.
El validador verificó los blobs de metadata y la igualdad profunda del JSON
**completo** del config frente al Docker archive probado `7ef5a28a…`, incluidas
configuración, historial y rootfs de 12 capas: difiere su serialización. No se
publica ese JSON. La DB existente registra actualización
`2026-11-13T19:05:12.362756469Z`, SHA-256
`cf51a5a8c8421b80becfd304d0beac86f6e7e97412f6500512781e55aa3def3c`.
El hash identifica el cache suministrado por la ejecución; Trivy no lo incorpora
de forma independiente en el reporte.

Los resultados no sustituyen los scanners de cada imagen ni sus bloqueos de
CI/release. Bandit de la fuente revisada registra **71 LOW, 12 MEDIUM y 0 HIGH**.
Los hallazgos reales permanecen registrados, sin aceptaciones o
excepciones. La validación de Cloud Run/Jobs reales, GCS/IAM, IAP y VM/TLS queda
pendiente de sus aprobaciones y ejecución en cloud.
La caída del commit SQL tras subir un original a GCS no se inyectó en esta
aceptación; queda pendiente verificar su compensación o reconciliación.

Invocación sobre recursos nuevos ya preparados:

```text
python scripts/run_int_e2e.py --scratch <directorio-privado-externo> \
  --runtime-image sha256:<id-runtime> --browser-image sha256:<id-browser> \
  --postgres-image postgres@sha256:<digest> \
  --fixture <MP4-sintetico-externo> --user 10001:10001
```

El emulador debe estar descargado previamente con el digest fijo del lanzador.
La voz sintética sirve para comprobar el recorrido técnico; no demuestra la
calidad de transcripción con voces o grabaciones reales de producción.
