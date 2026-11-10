# ClipForge AI — Estado del proyecto

Fecha del snapshot: 2026-10-30. Aplicación base: **v0.4.1**. Roadmap: **revisión 1.0 propuesta**.

## Confirmado por el usuario

El MVP funciona localmente con Docker Desktop. Se generaron clips con imagen y audio. La interfaz reúne biblioteca, editor, estilos y propuestas. En v0.4.1 se recibieron tres propuestas de IA válidas tras corregir el contrato de intervalos.

No se registra aquí contenido de videos privados, credenciales ni IDs de trabajos de prueba del usuario.

## Implementado, con aceptación completa pendiente

Borradores, variantes, plantillas, aprobación y ZIP cuentan con pruebas previas documentadas. Falta confirmar en la instalación real el recorrido completo desde una propuesta de IA hasta el ZIP aprobado. Los tests del informe de v0.4.1 usan respuestas de proveedor simuladas y no ejecutaron su Docker ni Whisper real. No se ejecutó una nueva suite al escribir este plan.

## Restricciones vigentes

Local/single-operator, un proceso Uvicorn, almacenamiento en archivos y locks/hilos locales. Sin autenticación, tenancy ni validación de producción. No exponer el puerto del MVP a Internet. No considerar la biblioteca una frontera de acceso entre clientes.

## Próximo objetivo propuesto

v0.4.2: CF-001 a CF-005. Después: piloto privado GCP v0.5.0, sujeto a presupuesto/proyecto/región aprobados.

## Decisiones abiertas

Proveedor cloud final (GCP recomendado), proyecto propio y región, presupuesto total, corpus autorizado de aceptación, ubicación remota del repositorio, carga esperada y retención. Se puede avanzar en documentación/pruebas sin inventar estas decisiones; no desplegar recursos ni asumir autorizaciones de gasto.

## Fuera de alcance de este entregable

No se modifica el código, no se crea v0.4.2, no se provisiona nube, no se carga contenido, no se configura una cuenta de cobros ni se programa seguimiento automático.

## Trazabilidad

ZIP fuente inspeccionado: `clipforge-mvp-v0.4.1.zip`.
SHA-256: `38be5eeb39ba39af469d9c98590361eadc86273e1fa6b154fdc70b5750e21ec8`.
Se revisaron Compose, Dockerfile y marcadores de almacenamiento/ejecución de main.py para planificar la migración. Esto no es un inventario ni una auditoría de seguridad completos.

## Registro de actualización

| Fecha | Cambio de planificación | Estado |
|---|---|---|
| 2026-10-30 | Consolidar baseline v0.4.1, roadmap por gates y dos etapas de nube | Propuesto para ejecución |

Al retomar: leer este archivo, revisar la tarea activa de BACKLOG y no marcar una fase terminada hasta registrar su evidencia.
