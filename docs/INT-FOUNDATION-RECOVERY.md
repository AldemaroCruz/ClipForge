# FUNDACIÓN INT: preparación de recuperación

Esta preparación parte del apply parcial44208225603. No autoriza otro apply,
grants, imports efectivos, cambios de VM ni SQL. Se verificaron otra vez los
bytes actuales en temporal privado con admin@ixbalam.studio; el plan WIF
debe comprobar por sí mismo su acceso y conservar ese mismo estado.

## Antecedente verificado

| Campo | Referencia |
| --- | --- |
| bucket | `clipforgebeta2-tfstate-int` |
| name | `terraform/int/tf-int-01/default.tfstate` |
| generation | `1794961942265923` |
| serial | `5` |
| lineage | `813c84a2-2ef1-ceb3-177e-3a2c3b815066` |
| sha256 | `7b4018183c1df6652200efb620cc4d71d5b8c3d39b08e80588fdd98cf9262648` |

TF1.15.8, provider Google8.11.0; sin lock actual en la captura. Las generaciones
históricas de locks no se tratan como bloqueos activos. No se restauró ni
sobrescribió ninguna generación.

## Reconciliación actual

| Dirección registrada | Evidencia actual |
| --- | --- |
| `google_compute_address.postgres` | GET Compute200; same resource path |
| `google_compute_disk.postgres` | GET Compute200; same resource path |
| `google_compute_firewall.deny_egress` | GET Compute200; same resource path |
| `google_compute_firewall.https` | GET Compute200; same resource path |
| `google_compute_firewall.iap` | GET Compute200; same resource path |
| `google_compute_firewall.postgres` | GET Compute200; same resource path |
| `google_compute_instance.postgres` | GET VM200; same instance ID |
| `google_compute_instance_iam_member.protected_bootstrap` | GET IAM200; exact unconditional member/role |
| `google_compute_network.int` | GET Compute200; same resource path |
| `google_compute_route.egress` | GET Compute200; same resource path |
| `google_compute_router.egress` | GET Compute200; same resource path |
| `google_compute_router_nat.maintenance` | GET router200; exact NAT child present |
| `google_compute_subnetwork.private["postgres"]` | GET Compute200; same resource path |
| `google_compute_subnetwork.private["run"]` | GET Compute200; same resource path |
| `google_storage_bucket.private["backups"]` | GET bucket200; exact name |
| `google_storage_bucket.private["media"]` | GET bucket200; exact name |
| `google_storage_bucket_iam_member.backup_writer` | GET IAM200; exact unconditional member/role |
| `google_storage_bucket_iam_member.media["api"]` | GET IAM200; exact unconditional member/role |
| `google_storage_bucket_iam_member.media["worker"]` | GET IAM200; exact unconditional member/role |
| `terraform_data.boundary` | Local Terraform guard; no remote GCP object |

Son20 direcciones, incluida terraform_data.boundary; no20 objetos físicos deGCP.
Se contrastaron las22 no registradas:17 configuraciones/grants previstos no
están implementados y cinco bindings existen sin estar en este estado. No se
deduce de ello un contador de acciones del plan.

| Import propuesto individual | Recurso / rol / miembro |
| --- | --- |
| `google_secret_manager_secret_iam_member.runtime["api_password"]` | `clipforge-int-pg-app-password` / `roles/secretmanager.secretAccessor` / `serviceAccount:clipforge-api-int@clipforgebeta2.iam.gserviceaccount.com` |
| `google_secret_manager_secret_iam_member.runtime["migrate_password"]` | `clipforge-int-pg-migrator-password` / `roles/secretmanager.secretAccessor` / `serviceAccount:clipforge-migrate-int@clipforgebeta2.iam.gserviceaccount.com` |
| `google_secret_manager_secret_iam_member.runtime["worker_password"]` | `clipforge-int-pg-app-password` / `roles/secretmanager.secretAccessor` / `serviceAccount:clipforge-worker-int@clipforgebeta2.iam.gserviceaccount.com` |
| `google_secret_manager_secret_iam_member.version_publisher["app_password"]` | `clipforge-int-pg-app-password` / `roles/secretmanager.secretVersionAdder` / `serviceAccount:clipforge-deploy-int@clipforgebeta2.iam.gserviceaccount.com` |
| `google_secret_manager_secret_iam_member.version_publisher["migrator_password"]` | `clipforge-int-pg-migrator-password` / `roles/secretmanager.secretVersionAdder` / `serviceAccount:clipforge-deploy-int@clipforgebeta2.iam.gserviceaccount.com` |

Los cinco son incondicionales. Audit Logs registra a admin@ixbalam.studio
instalándolos durante el bootstrap del13nov, entre18:42:20Z y18:42:42Z. El
propietario confirmó que fue manual, sin otro estado/gestor. Su transferencia
propuesta a este workspace se expresa mediante import blocks de miembros,
nunca políticas autoritativas. Los accesos ajenos y el accessor preexistente de
la SA PostgreSQL se conservan. El plan sólo lee/importa en memoria; únicamente
un futuro apply aprobado podría persistir la gestión en el estado.

## Contrato y ejecución

[Contrato de recuperación](../config/int-foundation-recovery.json) y
[cinco import blocks](../config/int-foundation-recovery-imports.tf) se revisan
como fuentes separadas de las diez fuentes HCL originales. Estas últimas,
startup, providers, inputs y backend siguen idénticos a bb4d104. El helper
copia sólo el archivo import al módulo temporal y registra ambos fingerprints.

El contrato activo queda en modo recovery_preparation_only; conserva su
antecesor d319b0d byte por byte y rechaza expresamente el binario/manifiesto del
run44194990499, aunque su plazo original aún no haya vencido. No reescribe
los objetos originales. La aceptación de ese binario no aprueba el siguiente.

La ruta nueva añade un llamador y argumentos de planificación/import preview.
La huella SHA709 del driver permanece, pero **F-SAST-EXEC no se transfiere** a
esa nueva ruta ni a un futuro apply. Se analiza su closure y se mantienen las
detecciones nativas. F-VM-XML y F-AUDIT-0077 conservan identidad, límites y
vencimiento máximo27nov23:59:59 Guatemala; no se declaran remediadas/operativas.

El workflow int-foundation-recovery-plan.yml es dispatch-only, hosted, protegido
por int y por el SHA explícito de controles; WIF es el existente. Ejecuta una
planificación real con init readonly, refresh normal y locking nativo, sin
target/import CLI/state push/apply. Revalida generación/hash/serial y bindings
antes/después. Exige42 direcciones objetivo, preserva20, representa los cinco
imports de forma explícita y deriva los contadores del JSON nativo. No supone
22 ni17create. Un cambio material conserva el plan privado y mantiene failure.

Si hay plan, binario/JSON/manifiesto se guardan create-only en GCS privado, con
generación/SHA, backend parcial, ambas identidades de commit, lock/providers,
imagen y TTL nuevo de24h. No hay aprobación de apply ni ampliación de riesgos.
Si una lectura falla, se conserva su operación/permiso/recurso sin reintentar.

## Prerrequisitos y siguientes decisiones

- [Matriz y delta IAM](INT-FOUNDATION-RECOVERY-IAM.md): propuesta de administrador, no grants ejecutados.
- [Acceso verificable a VM](INT-FOUNDATION-VM-ACCESS.md): hostkeys/ respondió404; ninguna metadata/reinicio ejecutados.
- Deny de organización no pudo leerse (iam.denypolicies.list); no se afirma ausencia. Troubleshooter está deshabilitado y no se habilitó. Estas limitaciones no se convierten en un gate teórico de lecturas de recursos ausentes.
- Bootstrap SQL, guest inventory/SCA y prueba sintética de auditoría permanecen pendientes.
- CI de aplicación conserva sus gates; preparación de recuperación no habilita runtime, Cloud Run ni Jobs. DEV, operación, SEC-05 y caché rechazado se preservan.
