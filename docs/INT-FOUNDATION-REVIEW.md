# INT: decisión de foundation, sin ejecución

El plan del [run 43528573812](https://github.com/AldemaroCruz/ClipForge/actions/runs/43528573812)
contiene **42 creaciones, cero cambios destructivos**, fase `foundation`.
No crea Cloud Run, versiones de secretos ni una base PostgreSQL operativa.
Aplicarlo sí crearía recursos facturables y cambiaría IAM: VM, discos, red/NAT
y buckets entre ellos. **No se
ejecutó apply ni se autoriza ejecutarlo mediante este documento.**

El propietario aprobó el **diseño** de cifrado administrado por Google y retención
de auditoría de 30 días el 2026-11-13, Guatemala. No aprobó con ello la operación,
los residuales de seguridad, IAM, coste o apply. Las detecciones originales se
conservan. Esta revisión usa los summaries autorizados y el JSON privado exacto,
verificado por hash; no publica ese JSON, outputs, políticas completas ni secretos.

| Identidad vinculante | Valor |
| --- | --- |
| Repositorio / rama / Environment | `AldemaroCruz/ClipForge` / `ci/bootstrap-sec03` / `int` |
| Proyecto / número / región | `clipforgebeta2` / `816643438938` / `us-central1` |
| Commit del plan | `aa68d4a3228bf6a1092703285f05022c8727d99c` |
| Manifiesto privado | generación `1794613158433064`; SHA-256 `6f5dd879f288fdca587d30adbf54ad98db5ce4733b39d7c50a2516a1f7f8494a` |
| Binario a aplicar, si se autoriza | generación `1794613158020437`; 22.008 bytes; SHA-256 `41826c9951c2123d21c5afad87a567ffa5608aea6cf288178aa5626dc61cb3ea` |
| JSON revisado | generación `1794613158258874`; 135.002 bytes; SHA-256 `9ac8469de52170333edd868a3a14997b736774b6eb67b16b80ee99f3cf52604d` |
| Configuración / lock de proveedores | `4d23ddc3e8b22ea58e5e998e8b381291876f79ab562e3d15dd95ff5556476f31` / `89e2189a1b882ac5ad3ce74ad17a304e95cf7fa072b9ced86fce09e78b88b5fa` |
| Terraform / inputs | `1.15.8`; `stage=foundation`, `machine_type=e2-micro`, `secret_versions=null` |
| Digest de imagen vinculado, no publicado | `us-central1-docker.pkg.dev/clipforgebeta2/clipforge-int/runtime@sha256:d4b65631b30c26785ae18898cd826990fa20b4dce45015fb241ba108ddba7d49` |
| Backend / workspace esperado | `clipforgebeta2-tfstate-int` / `terraform/int/tf-int-01` / `default`; lineage `813c84a2-2ef1-ceb3-177e-3a2c3b815066`, serial `1` |
| Creado / caducidad original de 24 horas | `2026-11-13T23:39:17.873727Z` / **`2026-11-14T23:39:17.873727Z`**, equivalente a **2026-11-14 17:39:17.873727 en Guatemala** |

El commit de controles de foundation se revisa y autoriza por separado; no se
sustituye el commit del plan por ese commit. Cambiar HCL, startup, inputs, lock,
backend o superar el TTL requiere un plan nuevo. Una fecha de revisión del piloto
más larga no extiende estas 24 horas.

## Las 42 creaciones exactas

Las direcciones siguientes provienen del plan verificado, no de reconstruir un
plan a partir de contadores. `media` y `backups` son buckets GCS; `access` es un
bucket **Cloud Logging**, que no configura server access logging de GCS.

| # | Dirección Terraform | Nombre o alcance y finalidad / exposición propuesta |
| ---: | --- | --- |
| 1 | `google_compute_address.postgres` | `clipforge-int-base-postgres`: IP interna `10.80.1.2`; sin IP pública VM. |
| 2 | `google_compute_disk.postgres` | `clipforge-int-base-postgres-data`: 20 GiB `pd-standard`, `us-central1-a`, retenido. |
| 3 | `google_compute_firewall.deny_egress` | `clipforge-int-base-deny-other-egress`: deniega otra salida de la SA PostgreSQL. |
| 4 | `google_compute_firewall.https` | `clipforge-int-base-maintenance-https`: salida VM TCP/443 a Internet para mantenimiento. |
| 5 | `google_compute_firewall.iap` | `clipforge-int-base-iap-ssh`: TCP/22 desde `35.235.240.0/20`, dirigido a SA PostgreSQL. |
| 6 | `google_compute_firewall.postgres` | `clipforge-int-base-pg-from-run`: TCP/5432 desde `10.80.0.0/26`, dirigido a SA PostgreSQL. |
| 7 | `google_compute_instance.postgres` | `clipforge-int-base-postgres`: e2-micro, `us-central1-a`; privada, Shielded VM/OS Login; boot 10 GiB. |
| 8 | `google_compute_instance_iam_member.protected_bootstrap` | Deploy recibe OS Admin Login sólo sobre esa VM. |
| 9 | `google_compute_network.int` | `clipforge-int-base`: VPC propia, sin subredes automáticas ni rutas por defecto iniciales. |
| 10 | `google_compute_route.egress` | `clipforge-int-base-egress`: ruta `0.0.0.0/0` al gateway, con firewall/NAT descritos. |
| 11 | `google_compute_router.egress` | `clipforge-int-base-egress`: Cloud Router regional para NAT. |
| 12 | `google_compute_router_nat.maintenance` | `clipforge-int-base-maintenance`: NAT público sólo para subred PostgreSQL; no ingreso público. |
| 13 | `google_compute_subnetwork.private["postgres"]` | `clipforge-int-base-postgres`, `10.80.1.0/28`; Private Google Access, flow logs. |
| 14 | `google_compute_subnetwork.private["run"]` | `clipforge-int-base-run`, `10.80.0.0/26`; futura conexión privada Run, flow logs. |
| 15 | `google_iap_tunnel_instance_iam_member.protected_bootstrap` | Deploy recibe acceso de túnel IAP sólo a esa VM. |
| 16 | `google_logging_log_view.access` | Vista `pilot-access` del bucket Logging `clipforge-int-access`; Data Access. |
| 17 | `google_logging_log_view_iam_member.audit_reader` | Admin recibe lectura de esa vista; no es un grant al proyecto completo. |
| 18 | `google_logging_project_bucket_config.access` | `clipforge-int-access`, `us-central1`, retención 30 días; sin lock de retención propuesto. |
| 19 | `google_logging_project_sink.access` | Sink `clipforge-int-access`: Data Access de los dos buckets piloto hacia Logging. |
| 20 | `google_project_iam_audit_config.storage_access` | Habilitación propuesta `ADMIN_READ`, `DATA_READ`, `DATA_WRITE` para Storage en todo el proyecto; sin exenciones locales. |
| 21 | `google_project_iam_custom_role.bootstrap_reader` | Define `clipforgeIntBootstrapReader`, cuatro GET de metadata, sin listas/escrituras en ese rol. |
| 22 | `google_project_iam_member.bootstrap_reader` | Asigna ese rol de proyecto a Deploy. |
| 23 | `google_secret_manager_secret.runtime["bootstrap-admin"]` | Contenedor `clipforge-int-bootstrap-admin`, sin versión/payload. |
| 24 | `google_secret_manager_secret.runtime["postgres-ca"]` | Contenedor `clipforge-int-postgres-ca`, sin versión/payload. |
| 25 | `google_secret_manager_secret_iam_member.runtime["api_ca"]` | API: accessor de `clipforge-int-postgres-ca`. |
| 26 | `google_secret_manager_secret_iam_member.runtime["api_password"]` | API: accessor del contenedor existente `clipforge-int-pg-app-password`. |
| 27 | `google_secret_manager_secret_iam_member.runtime["bootstrap_admin"]` | Migrate: accessor de `clipforge-int-bootstrap-admin`. |
| 28 | `google_secret_manager_secret_iam_member.runtime["migrate_ca"]` | Migrate: accessor de `clipforge-int-postgres-ca`. |
| 29 | `google_secret_manager_secret_iam_member.runtime["migrate_password"]` | Migrate: accessor del existente `clipforge-int-pg-migrator-password`. |
| 30 | `google_secret_manager_secret_iam_member.runtime["worker_ca"]` | Worker: accessor de `clipforge-int-postgres-ca`. |
| 31 | `google_secret_manager_secret_iam_member.runtime["worker_password"]` | Worker: accessor del existente `clipforge-int-pg-app-password`. |
| 32 | `google_secret_manager_secret_iam_member.version_publisher["app_password"]` | Deploy: añadir versiones a `clipforge-int-pg-app-password`. |
| 33 | `google_secret_manager_secret_iam_member.version_publisher["bootstrap_admin"]` | Deploy: añadir versiones a `clipforge-int-bootstrap-admin`. |
| 34 | `google_secret_manager_secret_iam_member.version_publisher["migrator_password"]` | Deploy: añadir versiones a `clipforge-int-pg-migrator-password`. |
| 35 | `google_secret_manager_secret_iam_member.version_publisher["postgres_ca"]` | Deploy: añadir versiones a `clipforge-int-postgres-ca`. |
| 36 | `google_service_account_iam_member.protected_bootstrap` | Deploy: actuar como la SA existente PostgreSQL, sólo sobre esa cuenta. |
| 37 | `google_storage_bucket.private["backups"]` | `clipforgebeta2-int-backups`: privado, STANDARD regional, retención 30 días, expiración LIVE a 90 días. |
| 38 | `google_storage_bucket.private["media"]` | `clipforgebeta2-int-media`: privado, STANDARD regional, retención 7 días. |
| 39 | `google_storage_bucket_iam_member.backup_writer` | SA PostgreSQL: creador de objetos sólo en backups. |
| 40 | `google_storage_bucket_iam_member.media["api"]` | API: Object User sólo en media. |
| 41 | `google_storage_bucket_iam_member.media["worker"]` | Worker: Object User sólo en media. |
| 42 | `terraform_data.boundary` | Guard de proyecto/número y subredes; no es un recurso GCP facturable. |

Boot declara `auto_delete=false`; los datos son un recurso de disco separado,
con protección de destrucción en el código, al igual que la VM. La VM tiene
además deletion protection. Los dos buckets proponen UBLA, public
access prevention, versionado y soft delete de siete días; retenciones sin lock.
El borrado de versiones archivadas exige conjuntamente 30 días no actuales y
tres versiones más nuevas. Esto no demuestra backups creados ni restore.
El disco boot y las IP NAT automáticas son objetos implícitos, no direcciones
Terraform adicionales en esta cuenta de 42.

## IAM propuesto: 19 bindings y un rol definido, sin otorgarlos ahora

`api`, `worker`, `migrate`, `deploy` y `postgres` significan las SA existentes
`clipforge-<nombre>-int@clipforgebeta2.iam.gserviceaccount.com`. No se crean SA,
claves ni grants a `allUsers`/`allAuthenticatedUsers`. La tabla describe estos
grants; no sustituye una revisión del IAM efectivo/heredado completo.

| Principal | Rol | Recurso / bindings | Finalidad y alcance |
| --- | --- | --- | --- |
| api | `roles/secretmanager.secretAccessor` | PG app password + CA / 2 | Leer versiones para conexión de aplicación/TLS. |
| worker | `roles/secretmanager.secretAccessor` | PG app password + CA / 2 | Conexión worker/TLS. |
| migrate | `roles/secretmanager.secretAccessor` | PG migrator password + CA + bootstrap admin / 3 | Migración y bootstrap protegidos posteriores. |
| deploy | `roles/secretmanager.secretVersionAdder` | Los cuatro contenedores nombrados / 4 | Publicar versiones después; este rol no concede lectura. |
| deploy | `roles/compute.osAdminLogin` | Una VM / 1 | Administración OS para bootstrap; permite sudo, no es acceso de sólo lectura. |
| deploy | `roles/iap.tunnelResourceAccessor` | Esa VM / 1 | SSH mediante IAP. |
| deploy | `roles/iam.serviceAccountUser` | SA postgres / 1 | ActAs sobre esa identidad VM. |
| deploy | `projects/clipforgebeta2/roles/clipforgeIntBootstrapReader` | Proyecto / 1 | `compute.instances.get`, `compute.disks.get`, `compute.projects.get`, `run.operations.get`; GET de alcance proyecto. |
| api | `roles/storage.objectUser` | Bucket media / 1 | Lectura/escritura, incluida capacidad de borrar objetos; propiedad por usuario se controla en la aplicación. |
| worker | `roles/storage.objectUser` | Bucket media / 1 | Leer originales, publicar y limpiar resultados de tareas. |
| postgres | `roles/storage.objectCreator` | Bucket backups / 1 | Crear backups; no acredita lectura/restore ni su automatización. |
| `user:admin@ixbalam.studio` | `roles/logging.viewAccessor` | Vista `pilot-access` / 1 | Lectura de esa vista de auditoría. |

La combinación Deploy + OS Admin + ActAs permite administrar el sistema VM;
no debe presentarse como una separación absoluta de acceso a futuros datos OS.
El sink al bucket Logging del mismo proyecto no necesita otra SA escritora ni
un grant `bucketWriter`, según [Google](https://docs.cloud.google.com/logging/docs/export/configure_export_v2).

## 42 → 52: fase runtime separada, aún sin plan de esa fase

Es una proyección exacta de los `count`/`for_each` del código: **cuatro recursos
Run y seis bindings adicionales**. No son diez creaciones observadas en el plan
foundation. Requiere plan nuevo, recibo de foundation/post-state verificado,
imagen publicada por digest, versiones numéricas de secretos, PG/TLS/roles
configurados y los controles de aplicación; no habilita bootstrap o despliegue.

| Dirección adicional | Finalidad / exposición propuesta |
| --- | --- |
| `google_cloud_run_v2_service.api[0]` | `clipforge-int-api`: endpoint HTTPS público protegido por IAP y auth propia; 0–1 instancias, 1 CPU/1 GiB; VPC privada para PG. |
| `google_cloud_run_v2_job.task["worker"]` | `clipforge-int-worker`: 2 CPU/4 GiB, una tarea/parallelism=1, sin endpoint HTTP, sin retries. |
| `google_cloud_run_v2_job.task["migrate"]` | `clipforge-int-migrate`: 1 CPU/1 GiB, migración protegida. |
| `google_cloud_run_v2_job.task["bootstrap"]` | `clipforge-int-bootstrap`: 1 CPU/1 GiB, administrador inicial protegido. |
| `google_cloud_run_v2_service_iam_member.iap_invoker[0]` | Agente IAP `service-816643438938@gcp-sa-iap.iam.gserviceaccount.com` → `roles/run.invoker` en API. |
| `google_iap_web_cloud_run_service_iam_member.pilot_admin[0]` | Admin → `roles/iap.httpsResourceAccessor` en API. |
| `google_cloud_run_v2_job_iam_member.api_worker[0]` | SA api → `roles/run.invoker` en worker. |
| `google_cloud_run_v2_job_iam_member.protected_operator["worker"]` | SA deploy → `roles/run.invoker` en worker. |
| `google_cloud_run_v2_job_iam_member.protected_operator["migrate"]` | SA deploy → `roles/run.invoker` en migrate. |
| `google_cloud_run_v2_job_iam_member.protected_operator["bootstrap"]` | SA deploy → `roles/run.invoker` en bootstrap. |

## Coste mensual del escenario, no presupuesto ni factura

Desglose aritmético del estimador versionado `config/tf-int01-costs.json`, USD,
us-central1, 730 horas, sin descuentos/franquicias. Las tarifas públicas se
referencian en ese archivo. Se muestran cuatro decimales para no perder partidas
pequeñas; los totales se redondean después de sumar valores completos.

| Partida / supuesto | Foundation USD | Incremento runtime USD |
| --- | ---: | ---: |
| VM e2-micro, 730 h | 6.1148 | — |
| Boot 10 GiB pd-standard | 0.4000 | — |
| Datos 20 GiB pd-standard | 0.8000 | — |
| NAT: una VM, 730 h | 1.0220 | — |
| Una IPv4 NAT, 730 h | 3.6500 | — |
| NAT: 1 GiB procesado | 0.0450 | — |
| Media 10 + backups 10 GiB, incluyendo versiones/soft delete | 0.4000 | — |
| Auditoría 2 GiB, incluida posible copia `_Default` | 1.0000 | — |
| Telemetría/red 1 GiB: generación + almacenamiento | 0.5000 | — |
| Planes privados 0,1 GiB | 0.0020 | — |
| API 1 CPU/1 GiB, 2 horas activas | — | 0.1908 |
| API 100.000 requests | — | 0.0400 |
| Worker 2 CPU/4 GiB, 10 horas | — | 1.5840 |
| Operaciones administrativas Jobs, 20 minutos agregados | — | 0.0240 |
| Artifact Registry 4 GiB, modelo/revisiones incluidos | — | 0.4000 |
| Cuatro versiones activas de secretos | — | 0.2400 |
| 10.000 accesos a secretos | — | 0.0300 |
| GCS 10.000 clase A + 100.000 clase B | — | 0.0900 |
| Salida Internet 5 GiB | — | 0.6000 |
| **Total mensual** | **13.93** | **+3.20 = 17.13 completo** |

`base_infrastructure_monthly_usd=12.43` excluye logs/planes; por eso el campo
`pilot_additional_monthly_usd=4.70` del summary **no** es la diferencia contra
foundation 13.93. El ejemplo completo con e2-small es 23.25; no es el input
planeado. El texto original dice «tres Jobs administrativos»: el módulo tiene
dos administrativos y un worker; la partida sólo reserva 20 minutos agregados.

Los componentes de [NAT](https://cloud.google.com/nat/pricing),
[Run](https://cloud.google.com/run/pricing) y
[Logging](https://cloud.google.com/products/observability/pricing) son variables
según uso. Logging incluye 30 días en su tarifa; la franquicia publicada de
50 GiB/proyecto/mes no se descontó. El volumen supuesto no limita logs de otros
buckets al habilitar Storage Audit en todo el proyecto. No se consultó billing.
Se excluyen impuestos, transferencias adicionales/regionales, abuso y horas/logs
extra, versiones retenidas por encima del ejemplo, uso existente del bucket de
estado, cuotas GitHub, retries por capacidad y scanning opcional AR. No incluye
Cloud Build, IA externa, GPU, Redis, Cloud SQL, KMS ni un balanceador nuevo.

## PostgreSQL y protección: preparado no significa operativo

La imagen exacta resuelta por el plan es
`debian-cloud/debian-13-trixie-v20261109`; VM nueva, no una imagen PostgreSQL de
Docker. El startup autorizado tiene SHA-256
`a93bd662abce93b12c6389a37fccca49612ef3d1ee83eb882051cd5489daf255`.
Configura APT firmado de trixie/updates/security; instala
`postgresql-17=17.12-0+deb13u1` y cliente correspondiente, sin snapshot APT.
Esos pins se verificaron disponibles en la revisión separada
[INT-RUNTIME-CRITICAL.md](INT-RUNTIME-CRITICAL.md#vm-foundation-preflight-separado-sin-instalación-ni-scanner).

El script impide crear el cluster por defecto, enmascara PostgreSQL, no formatea
ni monta el disco, no ejecuta SQL, no recupera secretos ni habilita el servicio.
Disco/host key, inicialización explícita del disco vacío, TLS con SAN IP
`10.80.1.2`, roles SCRAM, versiones de secretos, arranque, backups y restore son
procedimientos posteriores. El servidor depende de libxml2: **`F-VM-XML` sigue
pendiente** como riesgo esperado, aunque el servicio quede masked/sin cluster y
no ejecute parsers de uploads. No hay inventario/SCA ni operación verificada de
esa futura VM; no se le atribuyen los findings de PG CI o del runtime multimedia.

## Auditoría: diseño aprobado, cobertura y observación separadas

Consultas autorizadas sólo de metadata, 2026-11-14 00:16:09–00:16:20 UTC
(2026-11-13 18:16 en Guatemala), proyecto fijo. Respuestas íntegras y errores
exactos quedan privados en el expediente `review-f470e37ec63b4724b329994772b4a942`,
subdirectorio `gcp-audit-qa-20261114`. Diez consultas GET: cuatro correctas,
seis NOT_FOUND/404 y ninguna denegación 403. No se leyeron log entries ni objetos,
ni se modificaron APIs, IAM o recursos.

| Control | Propuesto en el plan / código | Observado por lectura ahora |
| --- | --- | --- |
| Storage Audit | `storage.googleapis.com`: ADMIN_READ/DATA_READ/DATA_WRITE, sin exenciones locales; alcance proyecto. | `get-iam-policy` exitoso no devolvió auditConfig local para Storage ni `allServices`. Herencia org/folder no consultada: no se afirma deshabilitación efectiva global. |
| Buckets GCS piloto | Media/backups privados; sin `logging.logBucket` de server access logs. | Ambos `describe` devolvieron 404. No existe logging de esos buckets demostrado. |
| Bucket Logging piloto | `us-central1`, `clipforge-int-access`, retención 30 días. | 404 en ese nombre/localización. |
| Sink/vista/lector piloto | Data Access sólo media/backups; vista `pilot-access`; admin viewAccessor. | Sink, vista e IAM de vista devolvieron NOT_FOUND/404; no se afirma control desplegado. |
| `_Default` | No se modifica ni excluye en este módulo. | Sink existente dirige a `locations/global/buckets/_Default`; bucket ACTIVE, retención 30 días. Respuesta sin exclusiones explícitas ni `disabled=true`; filtro admite Data Access. |
| Writer/reader existentes | Sink al mismo proyecto: no nueva identidad escritora. | `_Default` sin writerIdentity; `_AllLogs` sin bindings directos devueltos. Se observó `roles/logging.logWriter` de proyecto para SA postgres, que no es un nuevo grant ni prueba acceso de lectura. No se evaluó IAM efectivo completo. |

`ADMIN_READ` es **Data Access**, no Admin Activity: cubre lecturas de metadata de
configuración; DATA_READ cubre datos/metadata/listados de objetos y DATA_WRITE
sus creaciones/modificaciones/borrados. El sink propuesto sólo selecciona
`cloudaudit.googleapis.com/data_access`; no toda la auditoría de administración.
[Clasificación y restricciones oficiales](https://docs.cloud.google.com/storage/docs/audit-logging).

El destino propuesto es el bucket Logging regional y su vista, no otro bucket
GCS. La [vista y viewAccessor](https://docs.cloud.google.com/logging/docs/logs-views)
acotan ese grant; no restringen por sí solos otros roles existentes. La activación
Storage no es por bucket. Los [sinks se evalúan independientemente](https://docs.cloud.google.com/logging/docs/routing/overview):
una copia `_Default` global puede coexistir con la regional y facturarse.
[Configuración heredada](https://docs.cloud.google.com/logging/docs/audit/configure-data-access)
y [sinks agregados/interceptores](https://docs.cloud.google.com/logging/docs/export/aggregated_sinks)
no se consultaron ni modificaron. No se acredita residencia exclusiva regional,
entrega real, inmutabilidad, ni ausencia de exclusiones en otras rutas.

Límites que permanecen en **`F-AUDIT-0077`**, las dos detecciones MEDIUM:

- Audit Logs no registra acceso público mediante `allUsers`/`allAuthenticatedUsers`
  ni cambios de Lifecycle/Autoclass; algunas descargas browser redactan identidad/IP.
  PAP privado es diseño, no evidencia operativa actual.
- Las [URLs firmadas](https://docs.cloud.google.com/storage/docs/access-control/signed-urls)
  son portadoras: no prueban por sí solas identidad del receptor. Storage soporta
  contexto de auditoría firmado; no se presume que se haya añadido. El proxy de
  aplicación usa SA, por lo que correlacionar al usuario de ClipForge exige
  evidencia adicional, sin registrar cookies, tokens o URLs firmadas completas.
- [AuditLog](https://docs.cloud.google.com/logging/docs/reference/audit/auditlog/rest/Shared.Types/AuditLog)
  describe metadata de operaciones; request/response no deben incluir contenido
  de archivos. Puede haber nombres/identificadores sensibles: no sustituye una
  copia del video, comprobación de integridad o backup y requiere acceso privado.
- [Usage/server access logs](https://docs.cloud.google.com/storage/docs/access-logs)
  son otra opción: CSV por bucket, almacenamiento GCS y permiso de creación para
  `cloud-storage-analytics@google.com`; incluyen detalle HTTP adicional y cubren
  casos públicos/Lifecycle. Su entrega/completitud no está garantizada. No se
  han configurado ni se añadió un bucket/grant alternativo automáticamente.

Audit Logs **no rellena** la propiedad `logging` que exige GCP-0077. La retención
30 días aprobada no acepta equivalencia, límites o esas detecciones. Faltan pruebas
posteriores, autorizadas, de eventos reales read/write/delete, routing, acceso
positivo/negativo de lector y conservación; no se generan escrituras de prueba
ahora. El plan deja destino/writerIdentity del sink y algunos IDs/rol custom
computados; el destino descrito procede de su referencia HCL, no de un valor
operativo conocido. Las cinco detecciones LOW de claves también permanecen
visibles; el diseño Google-managed no añade custodia/revocación independiente.

## Siguiente decisión concreta de foundation

**Preparado para decisión del propietario, no para aplicar.** Deben resolverse
individualmente y quedar vinculados al plan/binario anterior y al commit de
controles exacto:

| Residual | Decisión pendiente, sin aceptación por este documento |
| --- | --- |
| `F-SAST-EXEC` | Sólo tres LOW originales: B404 `scripts/tf_int_plan.py:16`, B603 `:169` y B603 `:180`; ejecutables/argv/plugins de las herramientas. Ver [clasificación puntual](INT-FOUNDATION-SAST.md). No cubre todos los SAST ni otras fuentes. |
| `F-VM-XML` | Dependencia libxml2 esperada de PG 17 en la VM nueva, servicio masked/sin cluster, sin inventario/SCA de VM y sin trasladar aceptación del runtime. |
| `F-AUDIT-0077` | Dos MEDIUM por server access logging ausente; alternativa Audit Logs con alcance y límites anteriores, todavía no operativa. |

IAM de la tabla, coste, VM/startup y **42 direcciones únicamente** necesitan
autorización específica separada, más una **nueva aprobación manual de `int`**
para el control y plan exactos, dentro del TTL. No se autoriza replan silencioso,
`-target`, migración/adopción de estado o ampliación de permisos. La fundación
tiene su contrato propio; el fallo del CI de aplicación se conserva pero no se
usa como bloqueo genérico de esta decisión separada. Imagen, aplicación, Jobs,
bootstrap/secretos posteriores y fase runtime mantienen sus gates específicos.
Ninguna aprobación de foundation habilita esas acciones posteriores.

## Ruta concreta hasta E2E en INT

1. **Decidir foundation (42).** Resolver individualmente `F-SAST-EXEC`,
   `F-VM-XML` y `F-AUDIT-0077`, revisar IAM/coste/VM y autorizar expresamente las
   42 direcciones. Revisar el commit de controles y aprobar manualmente `int`
   para aplicar el mismo binario privado identificado arriba, dentro de su TTL;
   si vence o cambia la configuración, exigir otro plan y revisión.
2. **Verificar la VM creada, antes de habilitar PostgreSQL.** Obtener inventario
   y SCA propios de su imagen/paquetes reales; revisar `libxml2` y el startup
   ejecutado. Preparar por separado disco, TLS, roles y versiones de secretos,
   con autorización explícita, y comprobar backup/restore. PostgreSQL 18.6 de CI
   no acredita esta VM PostgreSQL 17 ni su seguridad u operación.
3. **Resolver los bloqueos de aplicación/runtime.** Corregir el CRITICAL del
   runtime y tratar cada HIGH y hallazgo SAST pendiente mediante su corrección o
   decisión individual; conservar los gates. Una imagen corregida obtiene un
   digest nuevo y necesita inventario/SBOM/SCA propios; el digest `d4b656…`
   revisado aquí conserva sus hallazgos y no se presume corregido.
4. **Preparar la fase runtime (52).** Exigir CI de aplicación válido, recibo
   verificado de foundation y sus bindings de estado, y un plan privado nuevo
   para el objetivo de 52 recursos. Revisar el digest inmutable y las versiones
   de secretos exactas de esa fase; esos mismos valores deben quedar vinculados
   al plan revisado y a su aplicación. La proyección de diez recursos de este
   documento no sustituye ese plan ni prueba permisos de despliegue.
5. **Aprobar y comprobar en GCP.** Obtener otra aprobación manual de `int` y
   aplicar ese mismo plan privado revisado, sin publicar binarios, estado ni
   secretos. Después ejecutar E2E con datos sintéticos: acceso IAP y login,
   upload, Whisper real, selección/edición/subtítulos, render, reproducción y
   descarga, reapertura tras reemplazo de API, aislamiento entre usuarios y
   objetos, Jobs/locking/recuperación, TLS y backup/restore. Los 20 pasos locales
   ya ejecutados no se repiten para presentar evidencia cloud: GCS, Cloud Run,
   Jobs e IAM reales permanecen sin comprobar hasta esa ejecución autorizada.
