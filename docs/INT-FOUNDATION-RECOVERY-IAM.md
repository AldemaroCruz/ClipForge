# RecuperaciÃ³n de fundaciÃ³n INT: propuesta IAM pendiente

Se preparan **seis roles temporales para Terraform**, concedidos por `admin@ixbalam.studio` sÃ³lo despuÃ©s de una autorizaciÃ³n nueva del paquete concreto. No se concediÃ³ ningÃºn permiso. No se cambia HCL, backend, WIF, int, CI, bootstrap ni instalaciÃ³n local. Terraform/deploy no se otorgan su propia autoridad.

El [contrato JSON](../config/int-foundation-iam-delta.json) separa evidencia, cobertura actual, derechos faltantes y lÃ­mites. El [emisor PowerShell](../scripts/propose_int_foundation_iam.ps1) **sÃ³lo escribe archivos externos**; no tiene modo ejecutor ni llama a GCP. Emitir una receta no la aprueba.

## Evidencia actual, acotada

Se consultaron Ãºnicamente las polÃ­ticas de proyecto/organizaciÃ³n, tres polÃ­ticas SA, definiciones de roles y cuatro respuestas IAM de secretos autorizadas en private-readonly. No se leyÃ³ estado ni payload/credenciales.

| Captura | Cobertura relevante de Terraform | Consecuencia |
|---|---|---|
| Browser de proyecto | `resourcemanager.projects.get/getIamPolicy` | No duplicar GET de polÃ­tica; falta Set |
| Compute instanceAdmin.v1 | `compute.instances.getIamPolicy/setIamPolicy` | No aÃ±adir otra concesiÃ³n Compute IAM |
| Secret viewer en dos passwords existentes | `secretmanager.secrets.get/getIamPolicy` | GET IAM sÃ­ estÃ¡ incluido; no extrapolar a secretos nuevos o Set |
| PostgreSQL SA | serviceAccountUser: `iam.serviceAccounts.get/actAs` | ActAs no equivale a administrar su polÃ­tica |
| SAs Terraform/deploy | serviceAccountViewer: `iam.serviceAccounts.get/getIamPolicy` | Captura limitada a esas SAs |
| IAM de postgres-ca y bootstrap-admin | Ambas respuestas 404 | Ausencia en la captura; no exigir lectura de inexistentes como gate universal |

Se preservan los roles actuales browser, Compute instance/network/security admin, storage admin, run admin y serviceUsageConsumer. La polÃ­tica de organizaciÃ³n consultada por el coordinador no sustituye una evaluaciÃ³n efectiva de herencia, grupos, condiciones o deny policies.

Audit Logs conserva **cuatro eventos code7** del principal Terraform: dos `google.cloud.secretmanager.v1.SecretManagerService.CreateSecret` para postgres-ca/bootstrap-admin (`secretmanager.secrets.create`); `google.logging.v2.ConfigServiceV2.CreateBucketAsync` para `projects/clipforgebeta2/locations/us-central1/buckets/clipforge-int-access` (`logging.buckets.create`); CRM SetIamPolicy sobre el proyecto (`resourcemanager.projects.setIamPolicy`, mensaje `Policy update access denied`). Son cuatro eventos, no un inventario completo de fallos.

El artefacto nativo acotado conserva IAP GetIamPolicy HTTP403, permiso `iap.tunnelInstances.getIamPolicy`, sobre `projects/clipforgebeta2/iap_tunnel/zones/us-central1-a/instances/clipforge-int-base-postgres`. Las referencias a `iam.roles.get` e `iam.serviceAccounts.getIamPolicy` carecen aquÃ­ del mensaje literal completo: no se inventa ni se atribuye una denegaciÃ³n Audit a cada permiso inferido.

El original `approved_same_plan_apply.log` fue eliminado en la limpieza autorizada. El log GitHub recuperado mide **128248 bytes** y no contiene las lÃ­neas completas Error. El summary retiene como mÃ¡ximo **10 errores**. Esta evidencia es acotada; no se presenta como historial completo.

## Orden de recuperaciÃ³n y cinco imports

Puede intentarse el plan WIF normal con los **cinco imports cuya procedencia verifica por separado el coordinador**, antes de nuevas concesiones. No se convierte la uniÃ³n teÃ³rica de 17 lecturas de recursos ausentes/no registrados en un gate del plan. El grafo/imports/estado registrado determina los Read reales; tampoco se promete de antemano que todas esas lecturas funcionen.

Los bloques import sÃ³lo se incorporan al mÃ³dulo temporal para la vista previa. El parser8.11.0 acepta `resource_name role member [condition_title]`, separado por espacios. Ejemplo:

```text
projects/clipforgebeta2/secrets/clipforge-int-pg-app-password roles/secretmanager.secretAccessor serviceAccount:clipforge-api-int@clipforgebeta2.iam.gserviceaccount.com
```

Admite project ID o nÃºmero; **conserva el segmento y no lo convierte mediante GetIamPolicy**. Usar project ID como en HCL. El import lee polÃ­tica, busca rol/tÃ­tulo exactos, compara miembro sin distinguir mayÃºsculas y normaliza email; rechaza binding ausente o condiciÃ³n ambigua. No llama Set. [Import comÃºn](https://github.com/hashicorp/terraform-provider-google/blob/67f96115b523ba050b11dad30237f14023667de8/google/tpgiamresource/resource_iam_member.go#L121), [parser Secret](https://github.com/hashicorp/terraform-provider-google/blob/67f96115b523ba050b11dad30237f14023667de8/google/services/secretmanager/iam_secret_manager_secret.go#L149).

Revisar el nuevo plan y sus acciones efectivas antes de cualquier apply. No ejecutar import CLI, state push, migraciÃ³n, eliminaciÃ³n o force-unlock. La receta IAM no ejecuta Terraform, bootstrap, SQL, tÃºneles, cargas de versiones o deploy. Ante un fallo nuevo, conservar la operaciÃ³n/scope y revisar; no hay reintentos automÃ¡ticos.

## Seis roles temporales propuestos

Todos los bindings caducan en una fecha elegida expresamente al generar la propuesta, **mÃ¡ximo dos horas** desde entonces y nunca despuÃ©s de **2026-11-28T05:59:59Z** (27nov23:59:59 UTCâˆ’6). El vencimiento se vuelve a comprobar antes de escribir. IDs incorporan expiraciÃ³n: una colisiÃ³n detiene Create, sin actualizar/reutilizar un rol. Las definiciones permanecen cuando el binding expira; eliminarlas requiere otra autorizaciÃ³n.

| Rol | Permisos propuestos | Scope |
|---|---|---|
| Project policy | `resourcemanager.projects.setIamPolicy`, `iam.roles.get/create` | Proyecto+TTL; GET de polÃ­tica ya cubierto por browser |
| Logging config | `logging.buckets.create/get`, `logging.operations.get`, `logging.sinks.create/get`, `logging.views.create/get/getIamPolicy/setIamPolicy` | Proyecto+TTL; no payload, update o delete |
| Secret create | `secretmanager.secrets.create` | Proyecto+TTL separado; sÃ³lo se pretende crear los dos contenedores del HCL |
| Two new secret policies | `secretmanager.secrets.get/getIamPolicy/setIamPolicy` | TTL AND servicio/tipo Secret AND dos resource.name exactos de contenedores nuevos |
| Fixed IAP VM policy | `iap.tunnelInstances.getIamPolicy/setIamPolicy` | PolÃ­tica IAP de instance ID `1670495097211408131`+TTL |
| PostgreSQL SA policy | `iam.serviceAccounts.getIamPolicy/setIamPolicy` | PolÃ­tica de SA PostgreSQL exacta+TTL |

CondiciÃ³n de secretos: `resource.service == "secretmanager.googleapis.com"`, `resource.type == "secretmanager.googleapis.com/Secret"` y nombres `projects/816643438938/secrets/` mÃ¡s **sÃ³lo** `clipforge-int-postgres-ca` y `clipforge-int-bootstrap-admin`. Usar **nÃºmero**, no ID de proyecto, para resource.name. No hay prefijo abierto/comodÃ­n. [Formato oficial](https://docs.cloud.google.com/iam/docs/conditions-resource-attributes).

El rol Secret se limita a los dos contenedores nuevos. Los passwords existentes conservan sÃ³lo sus grants actuales: viewer ya permite Get/GetIamPolicy y los cinco bindings importados deben permanecer **NO-OP**. No se concede SetIamPolicy adicional sobre ellos. Si el plan propone actualizar alguno de esos cinco imports, bloquearlo y solicitar una nueva revisiÃ³n, sin ampliar permisos automÃ¡ticamente. Secret Create se comprueba sobre el padre proyecto: **no se finge restringir por nombre un secreto ausente**. Logging Create tambiÃ©n se autoriza en padres. No se pide update/delete en este delta; si el nuevo plan los requiere, detenerse y justificar el caso.

No hay Owner/Editor, comodines de permisos, IAM de organizaciÃ³n, claves SA, `secretmanager.versions.access/add/get/list`, lectura de payload de logs ni roles.update/delete/list/undelete. Estas Ãºltimas ramas se describen abajo sin concederlas.

**Riesgo residual pendiente de autorizaciÃ³n especÃ­fica:** project SetIamPolicy permite modificar roles/principales, incluso conceder autoridad a la propia cuenta Terraform. Roles.Create permite definir otros roles de proyecto. El TTL del binding no contiene a un principal capaz de cambiar su polÃ­tica. Secret/IAP/SA SetIamPolicy tambiÃ©n pueden delegar acceso en sus recursos. La receta limita los grants directos y conserva terceros; no elimina esa capacidad ni registra aceptaciÃ³n.

Los grants permanentes de **deploy** del HCL los crearÃ¡ sÃ³lo un futuro apply aprobado: OS Admin Login de VM, IAP Tunnel Resource Accessor en esa VM, actAs sobre PostgreSQL y `clipforgeIntBootstrapReader` (`compute.instances.get`, `compute.disks.get`, `compute.projects.get`, `run.operations.get`). **No concederlos por separado ahora.** Esta propuesta no amplÃ­a aceptaciones previas de SAST/diseÃ±o, su vencimiento o la vigencia de un plan.

El coordinador observÃ³ la VM con ID numÃ©rico **1670495097211408131**. El paquete fija `projects/816643438938/iap_tunnel/zones/us-central1-a/instances/1670495097211408131` tanto en la validaciÃ³n como en el endpoint de la receta. Una VM recreada con el mismo nombre queda fuera de este grant: se debe revisar su identidad y generar otra propuesta. La captura histÃ³rica 403 conserva su ruta original por nombre; no se reescribe esa evidencia.

IAP documenta una polÃ­tica propia y los permisos get/setIamPolicy por **instancia individual**, con ruta `projects/PROJECT_NUMBER/iap_tunnel/zones/ZONE/instances/INSTANCE_ID_OR_NAME`; no requiere convertir este grant en IAP Admin de proyecto. Ambos permisos figuran **SUPPORTED** para custom roles. La receta usa esa polÃ­tica de instancia y sÃ³lo condiciÃ³n temporal: no intenta usar `resource.name` de IAP ni un campo condition global del request. La condiciÃ³n pertenece al binding de la polÃ­tica versiÃ³n3. [JerarquÃ­a IAP](https://docs.cloud.google.com/iap/docs/managing-access), [soporte de custom roles](https://docs.cloud.google.com/iam/docs/custom-roles-permissions-support). Esto verifica el diseÃ±o admitido, no una autorizaciÃ³n efectiva comprobada del nuevo rol.

## GeneraciÃ³n de receta, sin concesiones

El emisor exige un directorio absoluto local externo y nuevo, `-NoOverwrite` y expiraciÃ³n futura. Rechaza UNC/comodines/reparse points; no sobrescribe.

```powershell
$expiryForReview = [DateTimeOffset]::UtcNow.AddMinutes(90)
powershell -NoProfile -File .\scripts\propose_int_foundation_iam.ps1 `
    -OutputDirectory 'C:\Users\itres\AppData\Local\ClipForge\foundation-iam-proposal-NUEVO' `
    -ExpiresAt $expiryForReview -NoOverwrite
```

Emite seis JSON de roles, dos condiciones (incluida `condition-two-new-secrets.json`), mapa, manifiesto SHA256 y `admin-grants-after-authorization.ps1`. El manifiesto liga todos los archivos, generador y configuraciÃ³n. La futura receta mutante exige referencia de autorizaciÃ³n separada, SHA del manifiesto revisado y ruta explÃ­cita a gcloud instalado. Verifica admin activo y ausencia de impersonaciÃ³n/overrides. No imprime tokens, polÃ­ticas completas ni entorno.

SÃ³lo esa receta futura usa roles create (no update) y add-iam-policy-binding de proyecto/SA, preservando bindings ajenos. Para IAP hace POST Get versiÃ³n3, aÃ±ade un binding y POST Set con **etag leÃ­do**; ausencia de etag/conflicto detiene sin forzar/reintentar. Token/polÃ­tica quedan en memoria. Nada del emisor ejecuta la receta. [Crear rol](https://docs.cloud.google.com/sdk/gcloud/reference/iam/roles/create), [binding proyecto](https://docs.cloud.google.com/sdk/gcloud/reference/projects/add-iam-policy-binding), [binding SA](https://docs.cloud.google.com/sdk/gcloud/reference/iam/service-accounts/add-iam-policy-binding), [IAP](https://docs.cloud.google.com/iap/docs/managing-access).

## Matriz exhaustiva del provider fijado

Provider oficial8.11.0, commit `67f96115b523ba050b11dad30237f14023667de8`. ZIP Linuxamd64 SHA256 `7bdfabf1da462eacceb2d36a8331b35ce70a5f6e4538a14097c47d8958c4067d` coincide con lock. SÃ³lo se comparÃ³ el checksum publicado, sin inspeccionar binario instalado. [Checksums](https://releases.hashicorp.com/terraform-provider-google/8.11.0/terraform-provider-google_8.11.0_SHA256SUMS).

Incluye todos los mÃ©todos de los tipos pendientes, **no sÃ³lo derechos faltantes**. Update en la tabla describe el provider y no forma parte del delta. `cloud-platform` es scope OAuth, no concesiÃ³n IAM.

| Recurso | API / lectura / permiso | Create-update / permiso | Scope y funciones fuente |
|---|---|---|---|
| `google_project_iam_audit_config.storage_access` | cloudresourcemanager.googleapis.com/v1; `POST projects/clipforgebeta2:getIamPolicy` â†’ `resourcemanager.projects.getIamPolicy` | `POST projects/clipforgebeta2:setIamPolicy` â†’ `resourcemanager.projects.setIamPolicy` | projects/clipforgebeta2 (whole project IAM policy; storage.googleapis.com auditConfigs entry); google/tpgiamresource/resource_iam_audit_config.go#L82 / #L155; google/services/resourcemanager/iam_project.go#L124 / #L146 |
| `google_project_iam_custom_role.bootstrap_reader` | iam.googleapis.com/v1; `GET projects/clipforgebeta2/roles/clipforgeIntBootstrapReader` â†’ `iam.roles.get` | `POST projects/clipforgebeta2/roles; PATCH projects/clipforgebeta2/roles/clipforgeIntBootstrapReader when definition changes` â†’ `iam.roles.create; iam.roles.update only for a reviewed update` | projects/clipforgebeta2/roles/clipforgeIntBootstrapReader (create authorized on projects/clipforgebeta2); google/services/resourcemanager/resource_google_project_iam_custom_role.go#L123 / #L185 / #L244 |
| `google_project_iam_member.bootstrap_reader` | cloudresourcemanager.googleapis.com/v1; `POST projects/clipforgebeta2:getIamPolicy` â†’ `resourcemanager.projects.getIamPolicy` | `POST projects/clipforgebeta2:setIamPolicy` â†’ `resourcemanager.projects.setIamPolicy` | projects/clipforgebeta2 (binding custom bootstrap reader to deploy SA); google/tpgiamresource/resource_iam_member.go#L321 / #L367; google/services/resourcemanager/iam_project.go#L124 / #L146 |
| `google_logging_project_bucket_config.access` | logging.googleapis.com/v2; `GET projects/clipforgebeta2/locations/us-central1/buckets/clipforge-int-access` â†’ `logging.buckets.get` | `POST projects/clipforgebeta2/locations/us-central1/buckets:createAsync?bucketId=clipforge-int-access; PATCH bucket path for retention/description/locked; POST bucket:updateAsync only if analytics is changed` â†’ `logging.buckets.create; logging.buckets.update only for a reviewed update; logging.operations.get to poll asynchronous creation/update` | projects/clipforgebeta2/locations/us-central1/buckets/clipforge-int-access (create parent projects/clipforgebeta2/locations/us-central1); google/services/logging/resource_logging_project_bucket_config.go#L182 / #L224 / #L290 / #L345; google/services/logging/logging_operation.go#L52 |
| `google_logging_project_sink.access` | logging.googleapis.com/v2; `GET projects/clipforgebeta2/sinks/clipforge-int-access` â†’ `logging.sinks.get` | `POST projects/clipforgebeta2/sinks; PATCH projects/clipforgebeta2/sinks/clipforge-int-access` â†’ `logging.sinks.create; logging.sinks.update only for a reviewed update` | projects/clipforgebeta2/sinks/clipforge-int-access (create parent projects/clipforgebeta2); google/services/logging/resource_logging_project_sink.go#L72 / #L160 / #L202 |
| `google_logging_log_view.access` | logging.googleapis.com/v2; `GET projects/clipforgebeta2/locations/us-central1/buckets/clipforge-int-access/views/pilot-access` â†’ `logging.views.get` | `POST bucket/views?viewId=pilot-access; PATCH view path if filter/description changes` â†’ `logging.views.create; logging.views.update only for a reviewed update` | projects/clipforgebeta2/locations/us-central1/buckets/clipforge-int-access/views/pilot-access (create parent bucket); google/services/logging/resource_logging_log_view.go#L208 / #L306 / #L397 |
| `google_logging_log_view_iam_member.audit_reader` | logging.googleapis.com/v2; `POST view-path:getIamPolicy` â†’ `logging.views.getIamPolicy` | `POST view-path:setIamPolicy` â†’ `logging.views.setIamPolicy` | projects/clipforgebeta2/locations/us-central1/buckets/clipforge-int-access/views/pilot-access; google/services/logging/iam_logging_log_view.go#L204 / #L242; google/tpgiamresource/resource_iam_member.go#L321 / #L367 |
| `google_secret_manager_secret.runtime[postgres-ca/bootstrap-admin]` | secretmanager.googleapis.com/v1; `GET projects/clipforgebeta2/secrets/secret-id` â†’ `secretmanager.secrets.get` | `POST projects/clipforgebeta2/secrets?secretId=secret-id; PATCH projects/clipforgebeta2/secrets/secret-id only for metadata update` â†’ `secretmanager.secrets.create; secretmanager.secrets.update only for a reviewed metadata update` | projects/clipforgebeta2/secrets/clipforge-int-postgres-ca and .../clipforge-int-bootstrap-admin (create parent projects/clipforgebeta2); google/services/secretmanager/resource_secret_manager_secret.go#L461 / #L598 / #L686 |
| `google_secret_manager_secret_iam_member.runtime (7) and version_publisher (4)` | secretmanager.googleapis.com/v1; `GET projects/clipforgebeta2/secrets/secret-id:getIamPolicy` â†’ `secretmanager.secrets.getIamPolicy` | `POST projects/clipforgebeta2/secrets/secret-id:setIamPolicy` â†’ `secretmanager.secrets.setIamPolicy` | Only secrets clipforge-int-pg-app-password, clipforge-int-pg-migrator-password, clipforge-int-postgres-ca, clipforge-int-bootstrap-admin in clipforgebeta2; google/services/secretmanager/iam_secret_manager_secret.go#L179 / #L221; google/tpgiamresource/resource_iam_member.go#L321 / #L367 |
| `google_compute_instance_iam_member.protected_bootstrap (separate from IAP)` | compute.googleapis.com/compute/v1; `GET instance-path/getIamPolicy` â†’ `compute.instances.getIamPolicy` | `POST instance-path/setIamPolicy` â†’ `compute.instances.setIamPolicy` | projects/clipforgebeta2/zones/us-central1-a/instances/clipforge-int-base-postgres; google/services/compute/iam_compute_instance.go#L198 / #L240; google/tpgiamresource/resource_iam_member.go#L321 / #L367 |
| `google_iap_tunnel_instance_iam_member.protected_bootstrap` | iap.googleapis.com/v1; `POST iap-tunnel-instance-path:getIamPolicy` â†’ `iap.tunnelInstances.getIamPolicy` | `POST iap-tunnel-instance-path:setIamPolicy` â†’ `iap.tunnelInstances.setIamPolicy` | Logical fixed VM in project816643438938/zoneus-central1-a; provider constructs projects/clipforgebeta2/iap_tunnel/zones/us-central1-a/instances/clipforge-int-base-postgres (IAP docs canonical example uses project number); google/services/iap/iam_iap_tunnel_instance.go#L198 / #L241 / #L280; google/tpgiamresource/resource_iam_member.go#L321 / #L367 |
| `google_service_account_iam_member.protected_bootstrap` | iam.googleapis.com/v1; `POST service-account-path:getIamPolicy` â†’ `iam.serviceAccounts.getIamPolicy` | `POST service-account-path:setIamPolicy` â†’ `iam.serviceAccounts.setIamPolicy` | projects/clipforgebeta2/serviceAccounts/clipforge-postgres-int@clipforgebeta2.iam.gserviceaccount.com; google/services/resourcemanager/iam_service_account.go#L78 / #L98; google/tpgiamresource/resource_iam_member.go#L321 / #L367 |

El ciclo IAM es Get-modify-Set y Get de propagaciÃ³n; Set solo no basta. Proyecto/log-view/IAP/SA usan POST getIamPolicy; Secret usa GET :getIamPolicy y Compute GET /getIamPolicy. El SDK google.golang.org/api v0.310.0 fijado en go.mod confirma POST de SA. [Ciclo](https://github.com/hashicorp/terraform-provider-google/blob/67f96115b523ba050b11dad30237f14023667de8/google/tpgiamresource/iam.go#L109), [SDK exacto](https://github.com/googleapis/google-api-go-client/blob/v0.310.0/iam/v1/iam-gen.go#L18474).

Logging bucket create usa :createAsync y polling GET projects/P/locations/us-central1/operations/id (`logging.operations.get`). Los create de bucket/sink hacen GET previo y pueden entrar en Update si encuentran un objeto: esto **no autoriza adoptar objetos desconocidos**. El sink de bucket Logging en el mismo proyecto no necesita writer SA ni grant adicional de destino. [CreateAsync](https://docs.cloud.google.com/logging/docs/reference/v2/rest/v2/projects.locations.buckets/createAsync), [operations](https://docs.cloud.google.com/logging/docs/audit-logging#google.longrunning.Operations), [destino](https://docs.cloud.google.com/logging/docs/export/configure_export_v2).

DeletionPolicyFromDiff/ReadDefault son locales, sin red. Los updates sÃ³lo de deletion_policy pueden llamar al Read normal: necesitan su GET, no un permiso delete. No hay List API en estos CRUD/datasources configurados; la imagen usa nombre, no family/list. [Control local](https://github.com/hashicorp/terraform-provider-google/blob/67f96115b523ba050b11dad30237f14023667de8/google/tpgresource/utils.go#L180).

### Datasources explÃ­citos

| Dependencia | MÃ©todo y permiso | Scope / fuente |
|---|---|---|
| data.google_project.existing | `GET cloudresourcemanager.googleapis.com/v1/projects/clipforgebeta2` â†’ `resourcemanager.projects.get` | projects/clipforgebeta2; [provider](https://github.com/hashicorp/terraform-provider-google/blob/67f96115b523ba050b11dad30237f14023667de8/google/services/resourcemanager/resource_google_project.go#L792), [API](https://docs.cloud.google.com/resource-manager/reference/rest/v1/projects/get) |
| same project datasource: billing association metadata | `GET cloudbilling.googleapis.com/v1/projects/clipforgebeta2/billingInfo` â†’ `resourcemanager.projects.get` | projects/clipforgebeta2; no billing-account IAM grant; [provider](https://github.com/hashicorp/terraform-provider-google/blob/67f96115b523ba050b11dad30237f14023667de8/google/services/resourcemanager/resource_google_project.go#L365), [API](https://docs.cloud.google.com/billing/docs/reference/rest/v1/projects/getBillingInfo) |
| data.google_service_account.existing (6 explicit SAs) | `GET iam.googleapis.com/v1/projects/clipforgebeta2/serviceAccounts/SA-email` â†’ `iam.serviceAccounts.get` | only six clipforge-{terraform,deploy,api,worker,migrate,postgres}-int SAs; [provider](https://github.com/hashicorp/terraform-provider-google/blob/67f96115b523ba050b11dad30237f14023667de8/google/services/resourcemanager/data_source_google_service_account.go#L70), [API](https://docs.cloud.google.com/iam/docs/reference/rest/v1/projects.serviceAccounts/get) |
| data.google_secret_manager_secret.existing (two password containers) | `GET secretmanager.googleapis.com/v1/projects/clipforgebeta2/secrets/secret-id` â†’ `secretmanager.secrets.get` | only clipforge-int-pg-app-password / clipforge-int-pg-migrator-password; [provider](https://github.com/hashicorp/terraform-provider-google/blob/67f96115b523ba050b11dad30237f14023667de8/google/services/secretmanager/data_source_secret_manager_secret.go#L41), [API](https://docs.cloud.google.com/secret-manager/docs/reference/rest/v1/projects.secrets/get) |
| data.google_storage_bucket.state | `GET storage.googleapis.com/storage/v1/b/clipforgebeta2-tfstate-int` â†’ `storage.buckets.get` | the existing state bucket metadata; no objects from this datasource; [provider](https://github.com/hashicorp/terraform-provider-google/blob/67f96115b523ba050b11dad30237f14023667de8/google/services/storage/data_source_google_storage_bucket.go#L41), [API](https://docs.cloud.google.com/storage/docs/json_api/v1/buckets/get) |
| data.google_artifact_registry_repository.existing | `GET artifactregistry.googleapis.com/v1/projects/clipforgebeta2/locations/us-central1/repositories/clipforge-int` â†’ `artifactregistry.repositories.get` | fixed existing repository metadata; [provider](https://github.com/hashicorp/terraform-provider-google/blob/67f96115b523ba050b11dad30237f14023667de8/google/services/artifactregistry/resource_artifact_registry_repository.go#L1156), [API](https://docs.cloud.google.com/artifact-registry/docs/reference/rest/v1/projects.locations.repositories/get) |
| data.google_iam_workload_identity_pool_provider.existing | `GET iam.googleapis.com/v1/projects/clipforgebeta2/locations/global/workloadIdentityPools/clipforge-gh-int/providers/github` â†’ `iam.workloadIdentityPoolProviders.get` | fixed existing provider metadata; no change to claims/provider/IAM; [provider](https://github.com/hashicorp/terraform-provider-google/blob/67f96115b523ba050b11dad30237f14023667de8/google/services/iambeta/resource_iam_workload_identity_pool_provider.go#L644), [API](https://docs.cloud.google.com/iam/docs/reference/rest/v1/projects.locations.workloadIdentityPools.providers/get) |
| data.google_compute_image.debian and post-plan metadata review | `GET compute.googleapis.com/compute/v1/projects/debian-cloud/global/images/debian-13-trixie-v20261116` â†’ `compute.images.get` | public debian-cloud image; permission there is not supplied by a role on clipforgebeta2; [provider](https://github.com/hashicorp/terraform-provider-google/blob/67f96115b523ba050b11dad30237f14023667de8/google/services/compute/data_source_google_compute_image.go#L137), [API](https://docs.cloud.google.com/compute/docs/reference/rest/v1/images/get) |

Son siete permisos distintos de datasources; project get tambiÃ©n cubre GetBillingInfo y Secret get ya estÃ¡ en la primera tabla. La uniÃ³n teÃ³rica suma17: no gate previo universal ni rol solicitado. GetProject/GetZone/GetRegion/GetBillingProject locales no implican consultas remotas; estos Read no crean service identities ni habilitan APIs.

### Lifecycle no solicitado

| Rama | Permisos | LÃ­mite |
|---|---|---|
| Retirar audit config/IAM member | Mismos GetIamPolicy/SetIamPolicy | No DELETE aparte; no retirar terceros |
| Custom role PATCH | iam.roles.update | No solicitado; justificar si aparece en nuevo plan |
| Custom role DELETE/Undelete | iam.roles.delete/undelete | No solicitados; un rol activo previo exige import y uno soft-deleted puede entrar en Undelete: detenerse/revisar |
| Logging bucket/sink/view DELETE | logging.buckets.delete, logging.sinks.delete, logging.views.delete | No solicitados |
| Secret DELETE | secretmanager.secrets.delete | No solicitado; conservar prevent_destroy |
| List API | Ninguno para este plan/create | No conceder List como remedio genÃ©rico |

AuditorÃ­a IAM asocia ademÃ¡s iam.roles.list con DeleteRole/UndeleteRole; REST explicita delete/undelete y el provider no llama ListRoles. Registrar esa discrepancia, sin aÃ±adir List al mÃ­nimo plan/create. [Delete](https://docs.cloud.google.com/iam/docs/reference/rest/v1/projects.roles/delete), [undelete](https://docs.cloud.google.com/iam/docs/reference/rest/v1/projects.roles/undelete), [auditorÃ­a](https://docs.cloud.google.com/iam/docs/audit-logging).

Esta matriz no demuestra autorizaciÃ³n efectiva ni cubre refresh de otros Compute/Storage ya creados, autenticaciÃ³n, backend GCS de Terraform core o verificaciÃ³n VM posterior. Billing, APIs habilitadas, deny/org policies y cuota son controles distintos. Mantener sus mensajes y scopes sin ampliar IAM automÃ¡ticamente.
