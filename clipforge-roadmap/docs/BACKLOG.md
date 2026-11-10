# ClipForge AI — Backlog trazable

Fecha: 2026-10-30. Base: v0.4.1. Todas las tareas siguientes están **Propuestas**, no implementadas por este entregable.

Prioridad P0: bloqueante para su hito. P1: mejora necesaria/próxima. P2: optimización posterior. P3: diferida.

| ID | Hito | Prioridad | Tarea | Dependencias | Estado | Criterio de aceptación |
|---|---|---|---|---|---|---|
| CF-001 | 0.4.2 | P0 | Aceptación integrada real | — | Propuesto | Tres videos hablados; uno completa IA autorizada → ZIP; evidencia del MP4/SRT y audio. No disparar pruebas pagadas sin autorización. |
| CF-002 | 0.4.2 | P0 | Dependencias y artefacto reproducibles | CF-001 | Propuesto | Lock transitivo y base por digest; revisión/hash de modelo; misma imagen probada y desplegada; actualización deliberada y rollback. |
| CF-003 | 0.4.2 | P0 | Backup y restauración local | — | Propuesto | Backup consistente de datos sin claves; restauración en carpeta limpia con conteos/hash y apertura de borrador/export. |
| CF-004 | 0.4.2 | P0 | Repositorio, CI y evidencias | CF-002 | Propuesto | Build/test con dependencias exactas, scan y SBOM; tags/changelog; smoke offline y aceptación real separada. |
| CF-005 | 0.4.2 | P1 | Métricas por etapa y revisión humana | — | Propuesto | Tiempos, fallos, tokens, uso de disco y clips aprobados visibles; logs sin contenido privado; registro de minutos de revisión. |
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

## Primer incremento recomendado

**CF-001 a CF-005**, manteniendo una tarea principal en curso. CF-006 puede trabajarse como diseño y presupuesto, sin crear recursos. Después de validar CF-001/002/003/004, promover el hito v0.4.2 y comenzar el piloto privado.

## Plantilla de actualización

Para cada tarea registrar: responsable, commit/versión, entorno exacto, evidencia ejecutada, limitaciones, resultado de aceptación y bloqueo si existe. No sustituir una prueba real por un stub sin indicarlo.

## Definición de terminado

Código revisado, regresiones aprobadas, aceptación del alcance realizada, documentación/changelog actualizados, datos anteriores preservados y rollback/restauración aplicables comprobados. Los cambios de nube necesitan evidencia del entorno real; los de IA necesitan distinguir contrato probado de calidad editorial real.
