# ClipForge AI — Backlog trazable

Prioridad del propietario, 2026-11-10: **AUTH-01 local**, presupuesto de nuevos
servicios cero. Implementar login, usuarios, PostgreSQL y autorización por recurso
con candidata aislada. Pro/ESM, GCP, servicios pagos y comparación de distros
aplazados; bloqueos de release no impiden desarrollar/probar localmente.
OAuth social, correo externo, MFA, recuperación de contraseña y administración
de pertenencias compartidas quedan para incrementos posteriores. No hay registro
público, migración de datos reales ni worker multimedia en AUTH-01.
Véanse [AUTH-01.md](AUTH-01.md) y [registro de riesgos](RISK-REGISTER.md).

Las prioridades cloud que siguen son históricas, no autorizaciones vigentes.

Fecha: 2026-10-30. Base: v0.4.1. Actualizado para el código v0.4.2. Los criterios originales se conservan; ningún test simulado cierra la aceptación real.

Prioridad P0: bloqueante para su hito. P1: mejora necesaria/próxima. P2: optimización posterior. P3: diferida.

| ID | Hito | Prioridad | Tarea | Dependencias | Estado | Criterio de aceptación |
|---|---|---|---|---|---|---|
| CF-001 | 0.4.2 | P0 | Aceptación integrada real | — | En validación | Tres videos hablados; uno completa IA autorizada → ZIP; evidencia del MP4/SRT y audio. No disparar pruebas pagadas sin autorización. |
| CF-002 | 0.4.2 | P0 | Dependencias y artefacto reproducibles | CF-001 | En validación | Lock transitivo y base por digest; revisión/hash de modelo; misma imagen probada y desplegada; actualización deliberada y rollback. |
| CF-003 | 0.4.2 | P0 | Backup y restauración local | — | En validación | Backup consistente de datos sin claves; restauración en carpeta limpia con conteos/hash y apertura de borrador/export. |
| CF-004 | 0.4.2 | P0 | Repositorio, CI y evidencias | CF-002 | Parcial; CI/scan pendientes | Build/test con dependencias exactas, scan y SBOM; tags/changelog; smoke offline y aceptación real separada. |
| CF-005 | 0.4.2 | P1 | Métricas por etapa y revisión humana | — | En validación | Tiempos, fallos, tokens, uso de disco y clips aprobados visibles; logs sin contenido privado; registro de minutos de revisión. |
| CF-006 | 0.5.0 | P0 | Decisión de presupuesto y proyecto cloud | CF-005 | Propuesto | Proyecto propio, región y techo operativo aceptados; cotización incluye NAT, disco, backups, red y LLM; no confundir alertas con cap global. |
| CF-007 | 0.5.0 | P0 | Terraform y despliegue de imagen | CF-004, CF-006 | Propuesto | IaC versionada, estado protegido, registry, identidad CI sin clave estática; deploy/rollback del digest sin reconstruir. |
| CF-008 | 0.5.0 | P0 | VM privada y acceso del operador | CF-007 | Propuesto | Una VM, un proceso y trabajo pesado; SSH vía IAP con forwarding loopback; sin puerto 8080 público; egreso explícito presupuestado. |
| CF-009 | 0.5.0 | P0 | Secretos e identidad del workload | CF-007 | Propuesto | Secret Manager, SA dedicada mínimo privilegio y sin JSON keys; clave del proveedor fuera de Git, imagen y entregas. |
| CF-010 | 0.5.0 | P0 | Datos persistentes y restauración cloud | CF-003, CF-008 | Propuesto | Disco de datos separado, backup consistente y restore demostrado; reinicio conserva proyectos; cache regenerable; alertas de disco. |
| CF-011 | 0.5.0 | P0 | Migración piloto y rollback | CF-009, CF-010 | Propuesto | Un proyecto autorizado migrado con IDs/hash; entrega cloud completa; local preservado y sin doble escritura. |
| CF-012 | 0.6.0 | P0 | Separar API y ejecutor de tareas | CF-011 | Propuesto | Entrada CLI del worker reutiliza módulos; API no alberga inferencia/render durable en un thread; smoke equivalente local/cloud. |
| CF-013 | 0.6.0 | P0 | PostgreSQL e importador versionado | CF-012 | Propuesto | Schema de org/proyecto/job/artefacto/revisión; migración dry-run y rollback; integridad e importación legacy probadas. |
| CF-014 | 0.6.0 | P0 | GCS y uploads reanudables | CF-012 | Propuesto | Objetos privados, ownership conocido, cuotas, validación de finalización/tamaño y descarga autorizada; sin depender del FS efímero o FUSE para estados. |
| CF-015 | 0.6.0 | P0 | Cola durable y despacho idempotente | CF-013, CF-014 | Propuesto | Outbox/lease/heartbeat y reconciliación; duplicados sin entregas ni cobros deliberadamente duplicados; intención durable antes de confirmar. |
| CF-016 | 0.6.0 | P0 | Fallos, cancelación y reintentos | CF-015 | Propuesto | Retry técnico por etapa sin repetir Whisper si hay resultado válido; llamadas IA inciertas requieren reconciliación/consentimiento, no reenvío silencioso. |
| CF-017 | 0.6.0 | P1 | Benchmark Jobs vs worker VM | CF-012, CF-005 | Propuesto | Corpus representativo, memoria temporal, modelo cold/warm y costo por clip; elegir runtime por datos, no asumir GPU ni escalabilidad. |
| CF-018 | 0.7.0 | P0 | Login, organizaciones y roles | CF-013 | Propuesto | Autenticación integrada, miembros/invitaciones y roles; cada endpoint verifica identidad y pertenencia. |
| CF-019 | 0.7.0 | P0 | Aislamiento y pruebas negativas | CF-014, CF-018 | Propuesto | Dos organizaciones no pueden cruzar IDs/URLs/jobs/plantillas/descargas; firma de URL solo tras autorizar recurso; TTL y secretos no logueados. |
| CF-020 | 0.7.0 | P0 | Seguridad de medios y límites | CF-015, CF-018 | Propuesto | Decoder sin privilegios, límites tamaño/duración/CPU/memoria y egress según diseño; escaneo dependencias; pruebas de archivos inválidos y abuso. |
| CF-021 | 0.7.0 | P0 | Retención, borrado y consentimiento | CF-019 | Propuesto | Política visible para originales/exports/backup/IA; borrar es controlado y auditable; material autorizado; revisión de condiciones antes del piloto. |
| CF-022 | 0.7.0 | P1 | Portal de revisión y onboarding | CF-018, CF-019 | Propuesto | Dos clientes invitados pueden revisar su material y descargar aprobados; operador ve trazabilidad; sin publicar ni aprobar automáticamente. |
| CF-023 | 0.8.0 | P1 | Medición y oferta comercial | CF-005, CF-022 | Propuesto | Costo total y tiempo humano conocidos; paquetes con límites; dos pilotos pagados como objetivo, no resultado asumido. |
| CF-024 | 0.8.0 | P0 | Viabilidad del proveedor de pagos | CF-023 | Propuesto | Verificar país/entidad, liquidación y requisitos; elegir proveedor antes de implementar. No dar por disponible una marca. |
| CF-025 | 0.8.0 | P0 | Cuotas y cobro trazable | CF-015, CF-024 | Propuesto | Ledger por organización, reserva/reconciliación y eventos de pago idempotentes; límites probados; sin planes ilimitados iniciales. |
| CF-026 | Paralela; priorizar con uso | P1 | Flujo por proyecto y multiselección | CF-001 | Propuesto | Navegación sin scroll excesivo, selección IA→borradores por lote, progreso y estados claros; nunca autoriza nuevas llamadas implícitas. |
| CF-027 | Paralela; priorizar con uso | P1 | Calidad de transcripción y revisión | CF-005 | Propuesto | Corpus español corregido, comparar precisión/latencia; nueva transcripción versionada, conserva cambios humanos; avisos de baja calidad. |
| CF-028 | Posterior | P2 | Tiempos por palabra y formatos | CF-027 | Propuesto | Alineación real revisable, estilos adicionales y 1:1/4:5/16:9; cambios no rompen proyectos previos. |
| CF-029 | Posterior | P2 | Análisis largo con presupuesto | CF-005, CF-015 | Propuesto | Chunking visible con máximo de llamadas/tokens autorizado; deduplicación de propuestas y pruebas sobre límites; no truncación silenciosa. |
| CF-030 | 1.0 | P0 | Preparación operativa de lanzamiento | CF-019, CF-020, CF-021, CF-025 | Propuesto | Carga/SLO/restauración/incidentes/rollback probados; soporte y costos conocidos; bloqueantes de seguridad resueltos. |
| CF-031 | Fuera del camino crítico | P3 | Publicación social y reencuadre automático | CF-023 | Propuesto | Investigar APIs/permisos y calidad por tipo de video; iniciar solo con demanda validada y sin desplazar fiabilidad. |

## Hito C en INT

| ID | Entrega | Estado | Aceptación |
|---|---|---|---|
| C00 | Reutilización de la base de INT | Comprobado | Rama, revisiones, cuotas y componentes documentados en [Hito C](INT-HITO-C.md). |
| C01 | Entrada de hasta 2 GiB | Evidencia funcional en INT, promoción pendiente | [45924575800](https://github.com/AldemaroCruz/ClipForge/actions/runs/45924575800) verificó tres videos de 2.116.336.669 bytes, simultaneidad, reanudación, persistencia y aislamiento. Se restauró la base después de la pérdida del runner en [45932688939](https://github.com/AldemaroCruz/ClipForge/actions/runs/45932688939). [Cupo y reanudación](INT-HITO-C.md#punto-de-continuación). |
| C02 | Corrección rápida de subtítulos | Evidencia funcional en INT, promoción pendiente | Corrección comprobada en MP4/SRT/WebVTT, otros clips conservados y persistencia al volver a iniciar sesión tras el reemplazo. |
| C03 | Ajuste preciso de recortes | Evidencia funcional en INT, promoción pendiente | Dos recortes tardíos exportados, con PTS, audio y subtítulos comprobados sobre los archivos descargados. |

## Hito D en INT

| ID | Tarea | Estado | Criterio de aceptación |
|---|---|---|---|
| D01 | Buscar momentos por tema | Aceptado en INT | Consentimiento, evidencia de transcripción, dos temas y uno ausente, cobertura hasta el final, persistencia, borrador, MP4 y ZIP. |
| D00 | Referencias temporales de la transcripción | Validado en INT | Guardar tiempos por palabra derivados del audio, ligados al original y a la transcripción. Preparar proyectos anteriores bajo demanda y conservar su versión previa. |
| D02 | Crear clip desde la transcripción | Validado en INT | Seleccionar un intervalo continuo, revisarlo con audio, abrirlo como borrador y exportarlo individualmente y en el ZIP mixto. |
| D03 | Textos del paquete de publicación | Validado en INT | Preparar, corregir y guardar el título, la descripción y los hashtags para una variante exacta. Incluir esa revisión en el ZIP mixto. |
| E01 | Resaltar palabra actual | Validado en INT | Usar marcas de D00 en el editor y el MP4. Guardar ambos colores en las plantillas y mantener estáticas las frases sin marcas compatibles. |
| — | Publicación progresiva de clips | Pendiente | Publicar cada clip con su manifiesto y preservar recuperación, idempotencia, aislamiento y eliminación. |

D01 se aceptó en INT en `9e49209aad98f74428b50276836719fd5bd76310`. La primera prueba registró tres reservas, tres llamadas y tres respuestas de OpenAI. La aceptación final reutilizó esa evidencia y comprobó el editor, el MP4 y el ZIP mixto con cero llamadas adicionales. [Búsquedas reales](https://github.com/AldemaroCruz/ClipForge/actions/runs/46116426162/artifacts/15252033378) · [Aceptación final](https://github.com/AldemaroCruz/ClipForge/actions/runs/46120063759)

D00 y D02 están activos desde `e7145844fd9db57df9a5ad20593c8df2da00080f`. La prueba de 20 minutos con habla natural comprobó un proyecto nuevo y uno histórico, guardó una versión adicional cuando la alineación cambió el texto o la segmentación y conservó sus correcciones previas. La preparación histórica tardó 82 s en la prueba de INT. En la comparación local con 4 vCPU y 4 GiB, la transcripción tardó 15,1 s sin marcas y 17,3 s con marcas, con un pico del contenedor de 1,29 y 1,30 GiB. El tiempo hasta recibir los clips en INT fue de 130,9 y 234,8 s en una ejecución de cada versión. Esa medición incluye el tiempo en cola y el render. [Ejecución](https://github.com/AldemaroCruz/ClipForge/actions/runs/46153668496) · [Capturas, recibos y audio](https://github.com/AldemaroCruz/ClipForge/actions/runs/46153668496/artifacts/15267434009)

D03 está activo en INT desde `352e0f7f8fdbe6622dd5d798c7c735f43cea6274`. Una cuenta normal comprobó sugerencias sobre dos temas, edición y recuperación al volver a entrar, reutilización tras un cambio visual y descarga exacta de cinco variantes con cuatro revisiones de publicación. OpenAI devolvió ambas respuestas con `gpt-6-luna`. Se registraron dos reservas y dos llamadas bajo el límite de 100 reservas diarias UTC. La publicación progresiva, los montajes y la eliminación de silencios siguen fuera de D03. [Corrida protegida](https://github.com/AldemaroCruz/ClipForge/actions/runs/46159322368) · [Recibos, capturas y pines de reversión](https://github.com/AldemaroCruz/ClipForge/actions/runs/46159322368/artifacts/15270171551)

La comparación pareada posterior de D00/D02 usó dos ejecuciones por modo con la misma grabación de 20 minutos, 4 vCPU, 4 GiB y recortes de 13,000 y 10,167 s. Los MP4, SRT y VTT resultaron idénticos. El arranque local fue de 0,8 a 1,2 s. La transcripción del video promedió 14,3 s en el modo por segmentos y 15,7 s en el modo con marcas por palabra, y el render de las dos salidas rondó 1,5 s en ambos modos. La verificación local de los archivos tardó menos de 0,04 s. Los recibos de INT registran el total y la carga del original por separado. La carga del mismo archivo tomó 2,49 y 2,65 s. Sigue pendiente el desglose de la cola, el arranque en Cloud Run, el render de los recortes automáticos y la publicación de las salidas.

E01 está activo en INT desde `51da59c5992a88be5114fb69171dedaf9da24eb9`. Una cuenta normal comparó la vista previa y los MP4 de dos recortes de habla natural, de 00:00.720 a 00:04.060 y de 18:20.100 a 18:28.680. El recorte tardío conservó 24 referencias de palabra en orden, incluidos los extremos y las repeticiones. Durante la pausa conservó el color base. El ZIP reunió tres variantes y dos revisiones de publicación de D03. Los SRT y VTT de la pareja fueron idénticos. La aceptación hizo cero llamadas a OpenAI. [Corrida protegida](https://github.com/AldemaroCruz/ClipForge/actions/runs/46167894270) · [Capturas, MP4, audio y recibos](https://github.com/AldemaroCruz/ClipForge/actions/runs/46167894270/artifacts/15273392326)

En la pareja tardía con 4 vCPU y 4 GiB, el render pasó de 7,034 s a 7,114 s con resaltado. El pico RSS del mayor proceso hijo fue de 244,1 a 247,4 MiB. Desde la activación del proyecto nuevo hasta la confirmación del despacho pasaron 0,199 s. El worker entró 78,256 s después y tomó la tarea en otros 0,549 s. El worker registró 0,629 s de preparación, 0,240 s de descarga, 37,790 s de transcripción y alineación, 57,732 s de render y 2,192 s de publicación. La diferencia histórica de unos 104 s sigue sin atribución. [Recibo de las etapas](https://github.com/AldemaroCruz/ClipForge/actions/runs/46167894270/artifacts/15273392326)

La escucha humana queda pendiente. El artefacto conserva los WAV históricos del recorte 18:19.980–18:30.140 y ventanas de contexto alrededor de sus bordes. El recorte tardío de E01 aporta una comprobación nueva equivalente al segundo recorte histórico, cuyo audio y límites exactos faltan. Se guardaron los MP4 y el audio del original con contexto de ambos recortes de E01. [Muestras para escucha](https://github.com/AldemaroCruz/ClipForge/actions/runs/46167894270/artifacts/15273392326)

## Primer incremento recomendado

**CF-001 a CF-005**, manteniendo una tarea principal en curso. CF-006 puede trabajarse como diseño y presupuesto, sin crear recursos. Después de validar CF-001/002/003/004, promover el hito v0.4.2 y comenzar el piloto privado.

## Plantilla de actualización

Para cada tarea registrar: responsable, commit/versión, entorno exacto, evidencia ejecutada, limitaciones, resultado de aceptación y bloqueo si existe. No sustituir una prueba real por un stub sin indicarlo.

## Definición de terminado

Código revisado, regresiones aprobadas, aceptación del alcance realizada, documentación/changelog actualizados, datos anteriores preservados y rollback/restauración aplicables comprobados. Los cambios de nube necesitan evidencia del entorno real; los de IA necesitan distinguir contrato probado de calidad editorial real.

## Evidencia de v0.4.2

CF-001: CLI verifica artefactos y decodificación; corpus y aceptación humana pendientes. CF-002: captura transitiva y hashes de modelo desde el equipo; se hereda la imagen identificada, no se declara reproducible el build desde fuentes ni un RepoDigest inexistente. CF-003: round-trip sintético probado con propuesta aceptable después del restore; prueba Windows pendiente. CF-004: runners y changelog incluidos; no se creó un repositorio remoto, CI, SBOM o escaneo. CF-005: panel/métricas probados con API real, pendientes mediciones de producción. Véase TEST-REPORT.md.
