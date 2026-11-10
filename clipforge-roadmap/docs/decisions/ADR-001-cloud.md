# ADR-001 — Migración gradual a GCP

**Estado: propuesto, no aprobado/desplegado.** Fecha: 2026-10-30.

## Contexto

La versión local combina API, threads y estado JSON en disco. Se debe preservar lo que funciona, permitir operaciones remotas y posteriormente aislar clientes. La meta comercial no requiere exponer el panel actual.

## Recomendación

Primero una VM privada para un operador de confianza, con disco persistente, imagen inmutable, backup y SSH/IAP; mantener un proceso y ausencia de réplicas. Después separar API, archivos, metadatos y ejecución para migrar a Cloud Run/GCS/PostgreSQL/Jobs según mediciones. El mismo repositorio puede ofrecer entrypoints API y worker sin fragmentarse en muchos microservicios.

## Alternativas

| Alternativa | Evaluación |
|---|---|
| Seguir únicamente en local | Costo/impacto inicial menor; conserva dependencia de la PC y no valida operación remota. Sigue disponible como laboratorio. |
| VM privada con Compose | Menor cambio inicial; requiere parches/backup/operación y sigue siendo un único punto de fallo. Recomendada para piloto interno, no como HA ni multiusuario. |
| Cloud Run Service con el MVP sin cambios | No recomendado: persistencia y coordinación locales, tareas en threads; el escalado y lifecycle requieren adaptación. |
| Cloud Run + almacenamiento y workers desacoplados desde cero | Dirección del SaaS; mayor trabajo inicial y costo de servicios gestionados. Se implementa después del piloto. |
| Kubernetes/GKE | No justificado por la carga ni requisitos demostrados; reevaluar solo ante necesidad medible. |

## Guardrails

No abrir 8080 públicamente. El túnel SSH vía IAP accede al loopback remoto; IAP TCP directo no alcanzaría por sí solo un servicio ligado exclusivamente a localhost. VM sin IP pública requiere salida planificada para API externa/modelos. Backups consistentes y restauración preceden a migración. Secretos del proveedor en Secret Manager; no copiar `.env.ai` dentro de imágenes, Git o paquetes de datos.

GCS no es un reemplazo transparente del directorio de JSON con locks. Metadatos y coordinación van a una base transaccional; archivos grandes a objetos. No escribir en dos instalaciones sobre el mismo snapshot. Preservar IDs, procedencia y hashes en el importador.

No confundir login con aislamiento: antes de clientes invitados se implementan organizaciones/roles y comprobaciones de autorización en cada recurso. Un acceso privado del operador no necesita todavía el portal de clientes, pero tampoco autoriza abrirlo.

## Costos y reversibilidad

Presupuestar cómputo, disco, backups, NAT/IP, egreso, logs, registry, CI y LLM. Elegir Cloud SQL/Jobs/GPU después de medir; el presupuesto de alertas no se trata como corte global de gastos. Conservar la base local y un procedimiento de rollback/importación. Terraform no debe destruir datos activos por defecto.

## Criterios de revisión

Reevaluar si cambia el presupuesto, aparecen varios operadores simultáneos, aumentan los videos largos o el tiempo en cola, se requieren clientes en autoservicio, o el costo de la VM supera una alternativa medida. La VM piloto se retira solo después de validar datos y operación del reemplazo.

## Referencias

Las fuentes T1–T13 y la evidencia E1–E3 están en `../ROADMAP.md`. Este ADR es una propuesta de diseño derivada de ellas, no una garantía de rendimiento ni una descripción de infraestructura existente.
