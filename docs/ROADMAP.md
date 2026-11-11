> Actualización 2026-10-30: v0.4.2 tiene controles implementados y permanece EN VALIDACIÓN. Véase PROJECT_STATUS.md; los criterios de aceptación originales que siguen no se dan por cumplidos automáticamente.

# ClipForge AI — Roadmap de producto y nube

## Prioridad vigente: AUTH-01 local (2026-11-10)

El propietario prioriza funciones sin nuevas suscripciones ni servicios de pago:
presupuesto **cero**. El hito actual es autenticación, usuarios, espacios privados
y PostgreSQL local en una candidata aislada, con login y pruebas reales.
No depende de reabrir SEC-05, migrar de distribución ni contratar identidad.

Pro/ESM y los hitos cloud/comerciales de abajo quedan aplazados. El desarrollo
local continúa con riesgos registrados sin aceptarlos; publicación, release y
despliegue mantienen sus bloqueos. No se actualiza ni migra la instalación
operativa. OAuth social, correo externo, MFA y worker multimedia quedan en
backlog. Entrega y resultados: [AUTH-01.md](AUTH-01.md).

El roadmap restante se conserva como historia/propuesta futura, no como orden
vigente de ejecución ni autorización para crear infraestructura facturable.

**Revisión del plan:** 1.0 · **Fecha:** 2026-10-30 · **Base de la aplicación:** v0.4.1.
**Responsable de producto:** Aldemaro. **Estado:** propuesta de ejecución; ninguna fase futura está implementada por este documento.

## 1. Dirección

Convertir videos hablados propios o autorizados en clips revisables. Primero operar clipping como servicio con control editorial humano; después habilitar un SaaS de autoservicio. El foco continúa en podcasts, entrevistas y contenido educativo. Música, análisis automático de jugadas, publicación social y reencuadre automático no bloquean el primer piloto.

**Ruta recomendada:** local confiable → nube privada para el operador → procesamiento desacoplado → beta multiusuario → operación comercial → lanzamiento estable.

GCP es la primera opción propuesta por la experiencia del usuario, no una contratación ni decisión irrevocable. No se utilizarían proyectos, cuentas, datos o créditos de empleadores. Mantener el modo local como laboratorio y vía de recuperación; evitar dos instalaciones escribiendo simultáneamente sobre el mismo conjunto de datos.

## 2. Línea base y evidencia

| Capacidad | Estado real al redactar | Pendiente relevante |
|---|---|---|
| Carga, validación, Whisper, selección heurística y FFmpeg | Implementados; el usuario confirmó un procesamiento y clips con audio | Medir fiabilidad y rendimiento con un conjunto representativo |
| Biblioteca, edición de rangos, manuales, borradores, variantes y estilos | Implementados y con pruebas previas documentadas | Aceptación integrada en la imagen exacta |
| Plantillas, revisión y ZIP | Implementados y probados en el entorno descrito en E1 | Cerrar una entrega real desde una propuesta IA en el equipo del usuario |
| Selección asistida opcional | El usuario mostró tres propuestas aceptadas por v0.4.1 | Medir calidad editorial, correcciones y consumo por clip aprobado |
| Nube, cuentas y aislamiento entre clientes | No implementados | Obligatorios antes de abrir autoservicio |
| Pruebas de producción | No acreditadas por los tests existentes | El informe previo no ejecutó Docker ni Whisper/OpenAI reales en ese entorno |

No confundir validación estructural de una propuesta con fidelidad editorial ni un `/health` correcto con una transcripción completada. [E1, E2]

## 3. Hitos por versión

Las versiones son objetivos propuestos. Se avanza por evidencia, no por haber llegado a una fecha. No se establecen plazos ni se considera todo el roadmap un compromiso de alcance fijo.

| Hito | Alcance | Criterio para darlo por terminado |
|---|---|---|
| **v0.4.2 — Base reproducible** | Aceptación E2E, dependencias bloqueadas, imagen inmutable, backup/restore, métricas y guía operativa | Tres proyectos hablados autorizados; al menos una entrega IA completa; restauración en carpeta limpia; imagen exacta probada |
| **v0.5.0 — Piloto cloud privado** | GCP propio, Terraform, registry, una VM con Compose y disco persistente, acceso privado, secretos, monitoreo y backups | Misma entrega en nube; reinicio conserva proyectos; restauración probada; ninguna ruta pública sin protección |
| **v0.6.0 — Backend preparado para crecer** | API y worker separados, PostgreSQL, GCS, uploads reanudables, cola durable, idempotencia y migración | Reiniciar la API no pierde trabajos; mensajes duplicados no duplican entregas; migración/rollback comprobados |
| **v0.7.0 — Beta de clientes invitados** | Login, organizaciones, roles, autorización por recurso, cuotas, auditoría, retención y borrado | Pruebas negativas entre dos organizaciones; dos clientes de prueba completan el flujo sin acceder a datos ajenos |
| **v0.8.0 — Operación comercial** | Onboarding, oferta y cuotas basadas en consumo medido, medición por organización, pagos compatibles con la entidad/país y mejoras editoriales priorizadas | Clientes de pago con entregas repetibles, costo por clip conocido, soporte y límites operativos claros |
| **v1.0 — Lanzamiento controlado** | Restauración, carga, seguridad, runbooks, SLO medidos, upgrades/rollback, documentación y soporte | Evidencia de operación sostenida; no solo una demo ni promesas de disponibilidad no medidas |

Las mejoras visuales no deben retrasar backup, seguridad y medición. Cobrar un servicio de edición operado por Aldemaro no requiere abrir antes un SaaS multiusuario; el cliente recibe entregables por un canal autorizado, no acceso al panel privado.

## 4. v0.4.2: próximo incremento concreto

### Aceptación real

Usar tres videos hablados autorizados y distintos, incluyendo uno largo representativo. Ejecutar carga → transcripción → propuesta IA autorizada → borrador → corrección → variante → aprobación → ZIP. Escuchar cortes, contrastar títulos con audio y abrir el MP4/SRT del ZIP.

Una llamada pagada a IA sigue siendo opt-in. La suite normal puede usar stubs claramente etiquetados; la aceptación real se registra por separado y no se dispara automáticamente en cada commit.

### Reproducibilidad y operación

Crear o consolidar repositorio privado con tags, changelog y evidencias. Bloquear dependencias transitivas y base por digest con proceso explícito de actualización; fijar también la revisión del modelo de transcripción y conservar hashes. No actualizar bibliotecas a ciegas para cumplir un pin. Construir una imagen, probarla y promover ese mismo digest.

Agregar un backup consistente con la aplicación en reposo y verificar restauración. Respaldar originales, transcripciones, borradores, revisiones, propuestas y entregas; la caché de modelos es regenerable. Las credenciales no se incluyen en ZIP, Git ni backup editorial.

Instrumentar duración por etapa, fallo/código, uso de memoria/disco, tokens reportados y número de clips aprobados. Registrar tiempo humano de revisión de forma separada. Los logs operativos no contendrán transcripciones ni claves.

## 5. Nube en dos etapas

### Etapa A — GCP privado, sin reescribir el MVP

**Propuesta inicial de dimensionamiento, por validar:** una VM Linux x86_64 `e2-standard-4`, 4 vCPU y 16 GiB; disco de datos separado dimensionado con el corpus real (100 GiB como punto de partida de prueba), CPU sin GPU, un proceso Uvicorn y un trabajo pesado a la vez.

Acceso: navegador del operador → puerto local → túnel SSH sobre IAP → loopback de la VM → ClipForge. La app sigue escuchando hacia el host en `127.0.0.1:8080`; no abrir 8080 al mundo ni apuntar un túnel TCP directo de IAP a un puerto que solo escucha en loopback. IAP se usa para llegar a SSH y SSH reenvía al loopback remoto. [T2]

Infraestructura propuesta: Artifact Registry para la imagen; disco persistente para `data/`; bucket privado para respaldos; Secret Manager para credenciales del proveedor; cuenta de servicio dedicada con mínimos permisos; logs/alertas; Terraform y CI/CD. Las identidades adjuntas al cómputo evitan copiar claves JSON de cuentas de servicio. [T10]

Preferencia de red: VM sin IP pública. Para llamadas a un proveedor externo y descargas de modelos hay que presupuestar y configurar salida, por ejemplo Cloud NAT; Private Google Access no reemplaza salida a cualquier Internet. NAT, discos, red y respaldos son parte del costo, no extras invisibles. No se necesita un balanceador público en este piloto.

No ofrecer cuentas de cliente todavía. El piloto es para un operador de confianza. No hay escalado horizontal ni dos procesos sobre los JSON. El acceso privado no sustituye la autorización multiusuario que llegará después.

### Etapa B — Arquitectura para SaaS

Mantener Python/FastAPI y los módulos probados. Separar responsabilidades, no reescribir todo en Go ni introducir Kubernetes por defecto.

| Responsabilidad | Propuesta |
|---|---|
| UI y API | Cloud Run, sin datos durables en su filesystem ni trabajo pesado dependiente de un hilo de la API |
| Videos, subtítulos y entregas | GCS privado; objetos inmutables/versionados según política |
| Metadatos, revisiones, cuotas y jobs | PostgreSQL, con Cloud SQL como opción gestionada a presupuestar |
| Ejecución de transcripción/render | Cloud Run Jobs si benchmarks de CPU/memoria/espacio temporal lo permiten; VM worker como alternativa medida |
| Despacho | Cloud Tasks y un despachador corto o mecanismo equivalente, con outbox durable e idempotencia |
| Identidad de usuarios | Identity Platform como opción propuesta; roles y pertenencia validados por la API |
| Secretos, observabilidad y despliegue | Secret Manager, Logging/Monitoring y Artifact Registry/CI con identidad federada |

Cloud Run no es incompatible con ClipForge; **la implementación actual no debe migrarse allí tal cual**. El filesystem escribible predeterminado usa memoria y no persiste cuando termina la instancia. Un servicio también puede escalar a múltiples instancias, mientras el MVP tiene locks locales. [T1, E3]

No sustituir el disco de estado por GCS FUSE y asumir las mismas garantías: FUSE no es plenamente POSIX y no ofrece locking de archivos. Usar base de datos para coordinación y el API de objetos para artefactos. [T9]

Los uploads van directamente a GCS mediante una sesión reanudable autorizada. En Cloud Run el límite documentado para solicitudes HTTP/1 es 32 MiB, por debajo del máximo local de 300 MB; los uploads reanudables permiten continuar tras un fallo de red. Sesiones y URLs firmadas son credenciales bearer: emitirlas tras autorizar el recurso, enviarlas por HTTPS, no registrarlas y minimizar su exposición. [T4, T5, T6]

Los trabajos largos no se ejecutan dentro de una petición del navegador. Cloud Run Jobs admite tareas CPU de hasta 168 horas; no es una duración objetivo. Cloud Tasks limita los handlers HTTP a 30 minutos: usarlo para iniciar una ejecución durable, no mantener el render pendiente dentro de esa petición. [T7, T8]

Definir estados, heartbeat/leases, intentos, cancelación y recuperación. Se acepta una tarea después de persistir su intención; un reconciliador resuelve el intervalo entre guardar y despachar. Las etapas técnicas idempotentes pueden reintentarse de forma controlada. Una consulta a IA con resultado remoto incierto no se reenvía silenciosamente ni se considera libre de costo.

## 6. Funciones pendientes: orden de valor

**Prioridad alta:** navegación más compacta por proyecto; guardado y recuperación claramente visibles; cola/progreso; costos por trabajo; archivo/borrado seguro; restauración; selección/exportación de varios aprobados sin perder trazabilidad; mejor calidad de transcripción en español y detección de resultados poco fiables.

**Después de medir:** tiempos por palabra, resaltado de palabra activa, exportación 1:1/4:5/16:9, logos/títulos, versiones de plantillas, procesamiento de videos largos por lotes de análisis con límite explícito de consumo. Reprocesar transcripción genera una versión nueva, nunca reemplaza silenciosamente subtítulos corregidos.

**Diferibles:** reencuadre automático de rostros, publicación en redes, analítica de audiencia, aplicación móvil, marketplace, multicloud, Kubernetes y GPU permanente. La prioridad de estas funciones depende de feedback y economía del servicio; no son requisitos del primer ingreso.

## 7. Condiciones antes de invitar clientes

Autenticación no basta: cada lectura, descarga, edición, job, export, plantilla y entrega debe validar organización y rol en el servidor. Los identificadores aleatorios no equivalen a permiso. Añadir pruebas de acceso cruzado tanto en API como en URLs de objetos.

Limitar tamaños, duración, almacenamiento y trabajos concurrentes por organización; reservar consumo antes del trabajo y reconciliarlo después. Ejecutar decodificadores como usuario sin privilegios, con límites de recursos/tiempo y restricciones de acceso de red según el diseño. Mantener medios y dependencias actualizados sin romper la reproducibilidad.

Definir condiciones de uso, autorización del contenido, proveedores que reciben transcripciones y política de retención/borrado antes de usar material de clientes. No fijar periodos de retención a escondidas: la política debe ser visible y cubrir originales, variantes, propuestas, backups y enlaces compartidos. Preservar revisión humana previa a entrega.

Criterio negativo obligatorio: un usuario de organización A no puede listar, leer, descargar ni modificar ningún recurso de B aunque conozca su ID. La autenticación gestionada propuesta puede utilizar Identity Platform, pero la autorización de negocio debe implementarse y probarse en ClipForge. [T11]

## 8. Costos y economía

Referencia consultada: `e2-standard-4` (4 vCPU, 16 GiB), Iowa/us-central1, tarifa on-demand publicada de USD 0.13402284/h. Cálculos ilustrativos, solo cómputo, antes de créditos, impuestos o descuentos. Confirmar tarifa y configuración antes de crear recursos. [T3]

| Uso hipotético | Horas | Solo cómputo |
|---|---:|---:|
| 8 h × 22 días | 176 | USD 23.59 |
| Mes ilustrativo continuo | 730 | USD 97.84 |

No es el costo total: añadir disco, backups, GCS, descarga/egreso, NAT/IP si corresponde, logs, registry, builds y proveedor LLM. Al migrar a SaaS sumar la base de datos gestionada y la autenticación. Parar la VM no equivale a borrar ni dejar de cobrar recursos persistentes.

Una alerta de presupuesto no es un corte de consumo. Los spend caps disponibles tienen alcance/servicios elegibles y latencia; no asumir que protegen todos los costos de VM o almacenamiento. Combinarlos, cuando apliquen, con límites propios, apagado controlado y monitoreo. [T12, T13]

Medir costo operativo por clip aprobado: procesamiento + IA + almacenamiento + egreso + tiempo humano de revisión y soporte, dividido entre clips aprobados. Separar gasto variable de costo fijo. No ofrecer uso ilimitado ni definir precios definitivos antes de estas mediciones.

Objetivo comercial propuesto: dos pilotos pagados de servicio antes de invertir en autoservicio amplio. No es demanda validada ni ingreso garantizado. Para pagos del SaaS, verificar disponibilidad del proveedor para país, entidad y método de cobro antes de diseñar la integración.

## 9. Migración sin perder proyectos

Detener nuevos trabajos y esperar los activos; capturar snapshot/backup consistente; excluir secretos; inventariar y verificar hashes. Copiar primero un proyecto autorizado a un destino aislado y comprobar originales, subtítulos, borradores, propuestas, revisiones y ZIP. Conservar IDs y procedencia.

Durante la prueba, el local queda como referencia de solo lectura para ese snapshot. No escribir en local y nube pretendiendo sincronizar JSON automáticamente. Mantener la copia local intacta hasta comprobar aceptación y recuperación.

En la migración posterior a PostgreSQL/GCS: importador versionado, dry-run, conteos/hash, validación de referencias, prueba de rollback y copia de los originales. Un rollback de código no garantiza rollback del esquema; planificar ambos.

## 10. Seguimiento para no perder el hilo

El repositorio será la fuente de verdad: `docs/ROADMAP.md`, `docs/BACKLOG.md`, `docs/PROJECT_STATUS.md` y ADR de nube. Cada tarea tiene ID, prioridad, dependencia y criterio de aceptación. Estados: Propuesto → Listo → En curso → En validación → Hecho / Bloqueado.

No marcar «Hecho» solo porque exista código. Registrar versión/commit, resultado de tests, entorno y evidencia de aceptación. Mantener un incremento principal en curso y pocos pendientes simultáneos; nuevos deseos entran al backlog, no desplazan silenciosamente el objetivo activo.

**Siguiente incremento propuesto:** v0.4.2; cerrar aceptación, reproducibilidad y restauración. En paralelo solo diseño de infraestructura/Terraform, sin desplegar ni generar gastos hasta aprobar presupuesto, identidad de proyecto y región. Después, piloto cloud privado v0.5.0.

## Fuentes y base de evidencia

Consulta técnica: 30 de octubre de 2026. Revalidar precios, límites y disponibilidad antes de desplegar.

- **E1.** `clipforge-v0.4.1-test-report.md`, adjunto a la conversación: implementación, pruebas reales/simuladas y límites de la instalación local. Es un informe previo, no una nueva ejecución de pruebas para este roadmap.
- **E2.** Capturas y confirmaciones del usuario: procesamiento local, clips reproducibles y tres propuestas de IA aceptadas. No consta todavía la aceptación completa propuesta IA → borrador → MP4 → aprobación → ZIP en su equipo.
- **E3.** Inspección de `compose.yaml`, `compose.ai.yaml`, `Dockerfile` y marcadores de ejecución de `app/main.py` del ZIP v0.4.1: montajes locales, puerto loopback, un proceso Uvicorn y locks/hilos en memoria. No es una auditoría exhaustiva.
- **T1.** Google Cloud, contrato de contenedores Cloud Run: https://docs.cloud.google.com/run/docs/container-contract
- **T2.** Google Cloud, SSH a VM mediante IAP: https://docs.cloud.google.com/compute/docs/connect/ssh-using-iap
- **T3.** Google Cloud, precios de VM de propósito general: https://cloud.google.com/products/compute/pricing/general-purpose?hl=en
- **T4.** Google Cloud, cuotas Cloud Run: https://docs.cloud.google.com/run/quotas
- **T5.** Google Cloud, uploads reanudables: https://docs.cloud.google.com/storage/docs/resumable-uploads
- **T6.** Google Cloud, URLs firmadas y sesiones de upload: https://docs.cloud.google.com/storage/docs/access-control/signed-urls
- **T7.** Google Cloud, timeout de tareas Cloud Run Jobs: https://docs.cloud.google.com/run/docs/configuring/task-timeout
- **T8.** Google Cloud, tareas con destino HTTP: https://docs.cloud.google.com/tasks/docs/creating-http-target-tasks
- **T9.** Google Cloud, limitaciones Cloud Storage FUSE: https://docs.cloud.google.com/storage/docs/cloud-storage-fuse/overview
- **T10.** Google Cloud, Secret Manager: https://docs.cloud.google.com/secret-manager/docs/best-practices
- **T11.** Google Cloud, autenticación Identity Platform: https://docs.cloud.google.com/identity-platform/docs/concepts-authentication
- **T12.** Google Cloud, presupuestos y alertas: https://docs.cloud.google.com/billing/docs/how-to/budgets
- **T13.** Google Cloud, spend caps: https://docs.cloud.google.com/billing/docs/how-to/budgets-spend-caps
