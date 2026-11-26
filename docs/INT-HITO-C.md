# ClipForge INT · Hito C

## C00 · Base comprobada

La revisión inicial del portal responde con
`2b7b513e7892772b2d5fe222e9dee8c429f3a6e5`. La rama de entrega
`ci/bootstrap-sec03` de GitHub coincide con ese commit. El frontend
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

## Aceptación

Las mediciones de esta entrega se registran por incremento en el
[backlog](BACKLOG.md). Los resultados de límites y capacidad se atribuyen a
las revisiones donde se observó el recorrido completo.

### C02 · Corrección rápida

En **Mis trabajos**, abre un clip automático, pulsa **Corregir texto** y
edita la frase. **Guardar y exportar** crea una variante del clip con los
tiempos y el estilo existentes. El acceso a **Editar subtítulos** conserva
los controles de tiempos y estilo. La prueba local de Chromium usó
datos sintéticos y verificó persistencia de la corrección al recargar y
la disponibilidad de MP4, SRT y WebVTT para la nueva revisión.

### Reversión

Para revertir una entrega de INT se restaura el tráfico de la última
revisión aceptada de frontend/API y el digest aceptado del worker. El workflow
`int-hito-b.yml` conserva sus recibos de revisión e imagen y el procedimiento
de reversión de la beta. [Entrega y reversión](INT-HITO-B.md#entrega-y-reversión)
