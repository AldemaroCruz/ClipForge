# DB-01-NOBLE-PLAN · Perfil operativo de lectura

**Decisión única pendiente de ejecución.** Aprobar el delta versionado de IAM para `serviceAccount:clipforge-terraform-int@clipforgebeta2.iam.gserviceaccount.com` y una ejecución posterior del plan Noble con ese delta verificado. El acceso es operativo y estable. Esta propuesta sustituye la ventana del 20 al 24 de noviembre. Conserva WIF, los tokens de corta duración y la aprobación manual de `int`. Cada cuenta existente mantiene su función. Los accesos excepcionales de administración y guest conservan sus condiciones y sus vencimientos. [Matriz consolidada](DB-01-noble-read-matrix.md) · [Manifiesto operativo](../config/int-db01-noble-read-iam.json)

## Evidencia y reutilización

La observación `44608046539`, intento 1, commit `5c7bba01c77fd6b1ddbe1660cb84a9a7f72bce9d`, verificó 36 lecturas y confirmó 11 denegaciones HTTP 403 en ocho recursos. El ZIP corresponde a SHA-256 `6c13aac23fa06096bfa10e1579d3e9048ff8ba3fdfc116f26a0634cd6df41800`. El postcheck del mismo run verificó serial 7, generación `1795030868572779`, 42 direcciones, SHA-256 `aa2d7bf8d15d0fe3fb8461483483be2aa49ccede18c94d67a1f5a5a723ef13ce` y ausencia de lock el 19/11/2026 a las 14:36:33 de Guatemala. [Recibo WIF](https://github.com/AldemaroCruz/ClipForge/actions/runs/44608046539/artifacts/14570974972)

El 19/11/2026 a las 17:58 de Guatemala, `admin@ixbalam.studio` leyó las seis políticas afectadas y las definiciones completas. La revisión de políticas directas y la búsqueda de políticas del proyecto identificaron, para los ocho roles de lectura reutilizados, únicamente la cuenta Terraform mediante bindings históricos ya vencidos. Todos son roles personalizados en etapa GA de un solo permiso. Sus descripciones históricas se conservan. El vencimiento procede de las condiciones de los bindings anteriores. Añadir un binding operativo con condición propia conserva el alcance histórico y no modifica las definiciones ni los destinatarios anteriores. [Recibos históricos](../config/int-foundation-verification.json) · [Condiciones de IAM](https://docs.cloud.google.com/iam/docs/conditions-overview)

El rol compartido `clipforgeIntBootstrapReader` conserva su binding sin condición a Deploy y sus cuatro permisos `compute.disks.get`, `compute.instances.get`, `compute.projects.get` y `run.operations.get`. El rol histórico `clipforgeIntRecoveryIapPolicy_20261118T044838Z` incluye `iap.tunnelInstances.getIamPolicy` e `iap.tunnelInstances.setIamPolicy`. La lectura administrativa de las 18:01 de Guatemala devolvió HTTP 404 para el ID nuevo `clipforgeIntNobleIapPolicyRead`. El paquete crea esa única definición con `iap.tunnelInstances.getIamPolicy`, cuyo destinatario será Terraform en la instancia numérica fijada. [HCL de bootstrap](../infra/gcp/int-base/runtime.tf) · [Soporte de roles personalizados](https://docs.cloud.google.com/iam/docs/custom-roles-permissions-support)

## Delta IAM propuesto

La columna de rol indica el ID bajo `projects/clipforgebeta2/roles/`. Cada fila enumera todos los permisos de su rol. El delta añade **11 bindings en seis políticas**, con el principal Terraform como único miembro en cada binding nuevo. La escritura se agrupa por política. Los bindings observados y sus condiciones se conservan. Los bindings operativos carecen de condición salvo los dos predicados de recurso de Logging. El manifiesto fija las condiciones completas y la huella de la política base por destino. [Definiciones, bindings y orden](../config/int-db01-noble-read-iam.json)

| Rol | Permisos completos | Política de concesión y límite efectivo |
| --- | --- | --- |
| `clipforgeIntReadLogBucket_20261118T180000Z` | `logging.buckets.get` | Proyecto `clipforgebeta2`, con `resource.type == "logging.googleapis.com/LogBucket" && resource.name == "projects/clipforgebeta2/locations/us-central1/buckets/clipforge-int-access"`. |
| `clipforgeIntReadLogSink_20261118T180000Z` | `logging.sinks.get` | Proyecto `clipforgebeta2`. Abarca los metadatos de sinks del proyecto. El sink del grafo es `clipforge-int-access`. |
| `clipforgeIntReadLogView_20261118T180000Z` | `logging.views.get` | Proyecto `clipforgebeta2`, con `resource.type == "logging.googleapis.com/LogView" && resource.name == "projects/clipforgebeta2/locations/us-central1/buckets/clipforge-int-access/views/pilot-access"`. |
| `clipforgeIntReadLogViewPolicy_20261118T180000Z` | `logging.views.getIamPolicy` | Política de `projects/clipforgebeta2/locations/us-central1/buckets/clipforge-int-access/views/pilot-access`. |
| `clipforgeIntReadSecretMetadata_20261118T180000Z` | `secretmanager.secrets.get` | Políticas directas de `projects/clipforgebeta2/secrets/clipforge-int-bootstrap-admin` y `projects/clipforgebeta2/secrets/clipforge-int-postgres-ca`. |
| `clipforgeIntReadSecretPolicy_20261118T180000Z` | `secretmanager.secrets.getIamPolicy` | Las mismas dos políticas de Secret Manager, cada una por separado. |
| `clipforgeIntReadPostgresPolicy_20261118T180000Z` | `iam.serviceAccounts.getIamPolicy` | Política de `projects/clipforgebeta2/serviceAccounts/clipforge-postgres-int@clipforgebeta2.iam.gserviceaccount.com`. |
| `clipforgeIntReadRoleMetadata_20261118T180000Z` | `iam.roles.get` | Proyecto `clipforgebeta2`. Abarca GET de metadatos de roles personalizados del proyecto. El objeto del grafo es `clipforgeIntBootstrapReader`. |
| `clipforgeIntNobleIapPolicyRead` | `iap.tunnelInstances.getIamPolicy` | Política de `projects/816643438938/iap_tunnel/zones/us-central1-a/instances/1670495097211408131`. |

Los métodos `logging.sinks.get` e `iam.roles.get` requieren el ámbito de proyecto para este perfil. IAM Conditions documenta nombres de buckets y vistas de Logging, y no ofrece predicados de nombre equivalentes para un sink o un rol personalizado. Mantener esos dos roles de un solo permiso acota el alcance efectivo. La vista admite política directa para su lectura IAM. El paquete excluye el acceso a entradas de Logging y payloads de Secret Manager, cambios de política por Terraform y permisos de creación o borrado de infraestructura. [Atributos de recurso IAM](https://docs.cloud.google.com/iam/docs/conditions-resource-attributes) · [Política directa de vista](https://docs.cloud.google.com/logging/docs/reference/v2/rest/v2/locations.buckets.views/getIamPolicy) · [Política de instancia IAP](https://docs.cloud.google.com/iap/docs/managing-access#managing_access_via_the_api)

## Reconciliación de políticas y plan

La lectura administrativa halló que los `etag` de **11 direcciones** gestionadas en **seis políticas** difieren del serial 7 antes del grant. La aprobación identifica las huellas de política previas y los `etag` fijados en el estado. El operador añade el delta exacto, protege cada escritura con el `etag` vigente y relee los destinos. La comprobación conserva la política previa, el delta y el resultado exactos con custodia privada. El uso operativo se limita a esas diferencias y preserva todos los bindings ajenos, condiciones y auditoría. [Manifiesto operativo](../config/int-db01-noble-read-iam.json) · [Semántica de versiones y etag IAM](https://docs.cloud.google.com/iam/docs/policies)

La guarda Noble acepta únicamente la deriva de metadato `etag` de una dirección vinculada a una política aprobada, con coincidencia exacta de huella de origen y resultado y con los demás atributos íntegros. La acción nativa de la dirección sigue siendo `no-op`. Cualquier otra deriva, recurso desconocido, cambio de política ajeno, contenido no comprobado, importación, actualización, eliminación o reemplazo bloquea el plan. Los otros controles de backend, imagen, red, estado y custodia continúan vigentes. [Guarda Noble](../scripts/db01_noble_plan.py) · [Lectura IAM del proveedor 8.11.0](https://raw.githubusercontent.com/hashicorp/terraform-provider-google/v8.11.0/google/tpgiamresource/resource_iam_member.go)

## Secuencia de ejecución sujeta a aprobación

1. Fijar el SHA publicado del expediente y la huella del manifiesto. El administrador `admin@ixbalam.studio` verifica proyecto/número, autoridad original del operador, definiciones reutilizadas, ausencia del rol nuevo y vigencia de las seis políticas base. Una divergencia, una definición que ya exista o un destinatario ajeno requiere conciliar la evidencia antes de aplicar.
2. El administrador aplica el delta exacto con el operador versionado. Se conservan metadatos de entrada, política previa, delta por destino y política resultante en custodia privada. Ante un fallo parcial o un resultado indeterminado se releen únicamente las políticas y la definición afectadas. Las escrituras se detienen mientras exista incertidumbre.
3. En el workflow protegido, el paso WIF verifica las once lecturas nuevas con la identidad Terraform. El controlador fija la generación, hash y tamaño del comprobante IAM privado, relee las seis políticas y verifica el backend. Cualquier denegación, recurso inesperado, lock o cambio de serial, generación, huella o direcciones conserva el bloqueo. La aprobación manual de `int` protege el workflow y sus lecturas.
4. Con todas las verificaciones satisfechas, el controlador ejecuta un único plan Noble, sin repetir refresh fuera de su ejecución. El resultado requerido es salida nativa 2, **11 altas y 42 no-op**, con los tres recibos privados de custodia. El resumen conserva evidencia de cada comprobación. [Workflow Noble](../.github/workflows/int-db01-noble-plan.yml)

El operador exige un archivo JSON regular y privado con los campos siguientes, materializado a partir de la decisión final real del propietario. Esta propuesta todavía carece de ese archivo. El operador conserva la huella del JSON en el recibo privado. La protección de `int` sigue vigente en GitHub.

| Campo | Valor requerido |
| --- | --- |
| `schema` | `clipforge-db01-noble-stable-read-approval-1` |
| `decision` | `apply_exact_stable_read_and_plan_once_with_scoped_rollback` |
| `reviewed_commit` | SHA completo del commit publicado objeto de la decisión |
| `package_sha256` | SHA-256 canónico emitido por `describe` para ese paquete |
| `source_observation` | Objeto exacto del manifiesto para el run WIF `44608046539`, intento 1, con su commit y el SHA-256 del ZIP |
| `approval_ref` | Referencia real a la decisión del propietario, de 1 a 500 caracteres |

Desde el checkout exacto, ejecutar en PowerShell sólo cuando exista esa decisión. `$reviewedCommit` es el SHA completo publicado y `$approvalFile` es la ruta absoluta al JSON privado. Conservar el archivo de aprobación fuera del repositorio. Usar también dos rutas nuevas fuera del repo para la evidencia privada.

```powershell
$description = python -B -m scripts.int_db01_noble_read_iam describe
if ($LASTEXITCODE -ne 0) { throw 'Comprobar el manifiesto READ versionado' }
$packageSha = ($description | ConvertFrom-Json).package_sha256
$preflightReceipts = Join-Path ([IO.Path]::GetTempPath()) ('noble-read-preflight-' + [Guid]::NewGuid().ToString('N'))
$applicationReceipts = Join-Path ([IO.Path]::GetTempPath()) ('noble-read-apply-' + [Guid]::NewGuid().ToString('N'))
$publishedCommit = gh api repos/AldemaroCruz/ClipForge/branches/ci/bootstrap-sec03 --jq '.commit.sha'
if ($LASTEXITCODE -ne 0 -or $publishedCommit -ne $reviewedCommit) { throw 'El SHA revisado difiere de la rama publicada' }
$existing = gh run list --repo AldemaroCruz/ClipForge --workflow int-db01-noble-plan.yml --commit $reviewedCommit --event workflow_dispatch --json databaseId,status
if ($LASTEXITCODE -ne 0 -or @($existing | ConvertFrom-Json).Count -ne 0) { throw 'Comprobar el único dispatch Noble antes de continuar' }

python -B -m scripts.int_db01_noble_read_iam preflight --reviewed-commit $reviewedCommit --package-sha256 $packageSha --receipt-dir $preflightReceipts
if ($LASTEXITCODE -ne 0) { throw 'Preflight READ bloqueado' }

python -B -m scripts.int_db01_noble_read_iam apply --reviewed-commit $reviewedCommit --package-sha256 $packageSha --receipt-dir $applicationReceipts --approval $approvalFile
if ($LASTEXITCODE -ne 0) { throw 'Aplicación READ bloqueada. Conservar sus recibos.' }
$iamReceipt = Get-Content -Raw -LiteralPath (Join-Path $applicationReceipts 'iam-receipt-reference.json')

$existing = gh run list --repo AldemaroCruz/ClipForge --workflow int-db01-noble-plan.yml --commit $reviewedCommit --event workflow_dispatch --json databaseId,status
if ($LASTEXITCODE -ne 0 -or @($existing | ConvertFrom-Json).Count -ne 0) { throw 'Comprobar el único dispatch Noble antes de continuar' }
$dispatchInputs = @{ approved_commit = $reviewedCommit; iam_receipt = $iamReceipt.Trim() }
$dispatchInputs | ConvertTo-Json -Compress | gh workflow run int-db01-noble-plan.yml --repo AldemaroCruz/ClipForge --ref ci/bootstrap-sec03 --json
```

El recibo de `apply` es la referencia JSON con `name`, `generation`, `sha256` y `size` de un objeto inmutable en la custodia de planes existente. El nombre vincula el commit aprobado y la observación de origen. Se usan los permisos de custodia ya concedidos sobre ese bucket. El despacho entrega a GitHub sólo la referencia, mediante la entrada JSON de `gh`. [Manual de GitHub CLI](https://cli.github.com/manual/gh_workflow_run)

Para revertir, usar la carpeta de la aplicación original. El operador relee las políticas con versión 3 y usa sus `etag` actuales. Elimina únicamente el miembro Terraform en las tuplas exactas incorporadas por este paquete. Preserva los otros miembros, roles y condiciones. La definición IAP nueva queda sin asignación al retirar el binding del paquete. La reversión deja evidencia independiente de lo que efectivamente retiró. [Operador IAM estable](../scripts/int_db01_noble_read_iam.py)

```powershell
python -B -m scripts.int_db01_noble_read_iam rollback --reviewed-commit $reviewedCommit --package-sha256 $packageSha --receipt-dir $applicationReceipts --approval $approvalFile
```
