# DB-01-NOBLE-PLAN · propuesta READ para revisión

**Propuesta pendiente.** El run 44601130050 del commit `679f826f65937b6b0af1bf640634f5c96c6f37a3` confirmó cuatro denegaciones durante el refresh. La autorización siguiente debe identificar el SHA de este expediente, las tuplas aprobadas y la ventana exacta. La [matriz consolidada](DB-01-noble-read-matrix.md) conserva las demás lecturas, su dependencia y su vigencia. Una fila pendiente requiere una comprobación como Terraform antes de incorporarla al manifiesto. [Run y artefacto](https://github.com/AldemaroCruz/ClipForge/actions/runs/44601130050/artifacts/14569165724)

## Decisión propuesta

El único beneficiario del paquete es `serviceAccount:clipforge-terraform-int@clipforgebeta2.iam.gserviceaccount.com`. El propietario aprueba la selección y la ventana. `admin@ixbalam.studio` materializa y retira los bindings mediante su contexto administrativo existente. El controlador comprueba respuestas con la cuenta Terraform y el canal WIF protegido de `int`. Una lectura administrativa puede verificar definiciones y políticas, mientras que la comprobación efectiva usa la identidad beneficiaria.

Ventana nueva propuesta, **20/11/2026 08:00 inclusive a 23/11/2026 18:00 exclusivo de Guatemala**. En UTC, `2026-11-20T14:00:00Z <= request.time < 2026-11-24T00:00:00Z`. Abarca dos jornadas hábiles para verificar propagación, revisar los recibos y obtener la aprobación manual de `int`. Durante la ventana, el controlador puede volver a leer los mismos recursos con credenciales WIF nuevas de vida corta para cada observación autorizada. El coordinador confirma que queda tiempo suficiente para ejecutar el job de 30 minutos y revisar el resultado antes de programar el plan. Al completar la etapa o abortarla, el administrador retira los bindings exactos. Si se agota la ventana, la condición deja de conceder los permisos y una ventana nueva requiere otra autorización. La caducidad de la custodia del plan se calcula por separado. [Workflow Noble](../.github/workflows/int-db01-noble-plan.yml) · [Condiciones de tiempo](https://docs.cloud.google.com/iam/docs/conditions-attribute-reference#date-time)

`T` es el siguiente CEL común. `B` añade los dos predicados de bucket a `T`.

```cel
request.time >= timestamp("2026-11-20T14:00:00Z") &&
request.time < timestamp("2026-11-24T00:00:00Z")
```

```cel
resource.type == "logging.googleapis.com/LogBucket" &&
resource.name == "projects/clipforgebeta2/locations/us-central1/buckets/clipforge-int-access"
```

| ID | Política donde se añade el binding | Permiso único y definición de rol | Condición |
| --- | --- | --- | --- |
| `logbucket` | `projects/clipforgebeta2`, limitado al bucket exacto `clipforge-int-access` | `logging.buckets.get` mediante `projects/clipforgebeta2/roles/clipforgeIntReadLogBucket_20261118T180000Z` | B |
| `ca` | `projects/clipforgebeta2/secrets/clipforge-int-postgres-ca` | `secretmanager.secrets.get` mediante `projects/clipforgebeta2/roles/clipforgeIntReadSecretMetadata_20261118T180000Z` | T |
| `bootstrap` | `projects/clipforgebeta2/secrets/clipforge-int-bootstrap-admin` | El mismo rol de metadatos de Secret Manager | T |
| `iap` | `projects/816643438938/iap_tunnel/zones/us-central1-a/instances/1670495097211408131` | `iap.tunnelInstances.getIamPolicy` mediante el nuevo `projects/clipforgebeta2/roles/clipforgeIntNobleIapRead_20261124T000000Z` | T |

Los dos roles existentes se reutilizan sólo si la descripción actual confirma el conjunto exacto de permisos y que las definiciones están activas. Las concesiones históricas vencieron el 18/11 a las 20:15Z y la de gestión IAP fue retirada. El rol IAP histórico incluye `iap.tunnelInstances.setIamPolicy`. La definición IAP propuesta contiene sólo el permiso `getIamPolicy`, que Google admite en roles personalizados. La creación de esa definición es una operación futura del administrador, sujeta a la autorización del paquete. Una colisión de nombre suspende la operación para revisar la definición. El acceso al contenido de logs o secretos, creación de recursos, `actAs`, conexión por IAP, escritura de políticas por Terraform y cambios de WIF quedan fuera de las cuatro tuplas. [Recibos de la fundación](../config/int-foundation-verification.json) · [Niveles de soporte en roles personalizados](https://docs.cloud.google.com/iam/docs/custom-roles-permissions-support) · [Políticas de instancia IAP](https://docs.cloud.google.com/iap/docs/managing-access)

Para cerrar una sola autorización, incorporar a la selección sólo los faltantes que acredite la observación Terraform. Los siguientes roles de una sola lectura del expediente anterior permiten preparar esas filas sin modificar definiciones. Su disponibilidad, permisos vigentes y necesidad se verifican de forma independiente. [Definiciones y ámbitos históricos](../config/int-foundation-verification.json)

| Lectura por comprobar | Recurso | Ámbito mínimo comprobado históricamente y rol reutilizable |
| --- | --- | --- |
| `logging.sinks.get` | `projects/clipforgebeta2/sinks/clipforge-int-access` | Proyecto + T, `clipforgeIntReadLogSink_20261118T180000Z`. IAM documenta atributos de bucket y vista para Logging. El grant de sink histórico abarca metadatos de sinks del proyecto durante T. |
| `logging.views.get` | `projects/clipforgebeta2/locations/us-central1/buckets/clipforge-int-access/views/pilot-access` | Proyecto + T, tipo `logging.googleapis.com/LogView` y nombre exacto. `clipforgeIntReadLogView_20261118T180000Z`. |
| `logging.views.getIamPolicy` | La misma vista exacta | Política de la vista + T, `clipforgeIntReadLogViewPolicy_20261118T180000Z`. |
| `secretmanager.secrets.getIamPolicy` | Las políticas exactas de `clipforge-int-postgres-ca` y `clipforge-int-bootstrap-admin`, por separado | Política del secreto que falle + T, `clipforgeIntReadSecretPolicy_20261118T180000Z`. Las demás lecturas de Secret Manager, incluidos los dos secretos referenciados, se resuelven por la matriz y por evidencia de cada recurso. |
| `iam.serviceAccounts.getIamPolicy` | `projects/clipforgebeta2/serviceAccounts/clipforge-postgres-int@clipforgebeta2.iam.gserviceaccount.com` | Política de esa cuenta + T, `clipforgeIntReadPostgresPolicy_20261118T180000Z`. |
| `iam.roles.get` | `projects/clipforgebeta2/roles/clipforgeIntBootstrapReader` | Proyecto + T, `clipforgeIntReadRoleMetadata_20261118T180000Z`. La condición por nombre de custom role carece de soporte documentado. El grant permite leer metadatos de roles del proyecto durante T. |

Los casos de sink y rol tienen un ámbito efectivo más amplio que un único objeto. Ese ámbito debe figurar literalmente en el manifiesto si se confirma un faltante. Cada rol de la tabla se resuelve en `projects/clipforgebeta2/roles/`. Para una fila de proyecto se usa el comando de proyecto de abajo, y el comando específico de secreto, Logging View o cuenta de servicio para una fila directa. [Atributos de recurso de IAM](https://docs.cloud.google.com/iam/docs/conditions-resource-attributes) · [Binding de vista](https://docs.cloud.google.com/sdk/gcloud/reference/logging/views/add-iam-policy-binding) · [Binding de cuenta de servicio](https://docs.cloud.google.com/sdk/gcloud/reference/iam/service-accounts/add-iam-policy-binding)

## Materialización y comandos para la autorización posterior

Usar el patrón de [administrador, recibos y guardas](../scripts/propose_int_foundation_iam.ps1) del paquete anterior con la selección de esta tabla. Sus modos históricos contienen roles y recursos propios de la fundación. Para la propuesta Noble, revisar que el manifiesto exacto contenga proyecto/número, actor, miembro, filas, fechas, huellas de condiciones y división entre rol existente y definición nueva. Preservar el índice de recibos fuera de Git. Cada recibo liga operación, ID, ámbito, rol, condición, UTC, estado HTTP o salida nativa y resultado. Guardar las políticas y credenciales sólo en memoria. Los cuatro archivos de condiciones y el rol propuesto van en una carpeta privada del administrador para esta autorización.

Antes de cualquier escritura, comprobar vigencia, proyecto, autoridad administrativa, ausencia de impersonación y de overrides del CLI, definiciones con `gcloud iam roles describe` y políticas de los cuatro destinos con versión solicitada 3. Usar un `etag` actual para el cambio y verificar que cada tupla aún falta y el cambio deja iguales todos los bindings ajenos y `auditConfigs`. Repetir comprobaciones de identidad, selección y tiempo antes de cada mutación. Coordinar con los otros controladores del mismo estado para que el grant, la planificación y la retirada queden serializados.

La siguiente receta fija las condiciones que se materializarían como `condition-logbucket.json`, `condition-ca.json`, `condition-bootstrap.json` y `condition-iap.json`. Usar para cada archivo el título `clipforge-int-db01-noble-read-<ID>-20261124T000000Z`, la descripción `DB-01 Noble Terraform READ 2026-11-20T14:00:00Z to 2026-11-24T00:00:00Z` y `expression` igual a `T` o `(T) && B`, donde los símbolos se sustituyen por las expresiones CEL completas. Para IAP, la definición `role-iap.json` es exactamente:

```json
{
  "title": "ClipForge INT Noble IAP policy read",
  "description": "Read the IAM policy for the existing INT tunnel instance",
  "stage": "GA",
  "includedPermissions": ["iap.tunnelInstances.getIamPolicy"]
}
```

En PowerShell, después de comprobar el paquete autorizado, `$gcloud` apunta al ejecutable instalado y `$bundle` al directorio de los archivos revisados. Ejecutar cada comando por separado, capturar el código de salida y verificar el recibo antes del siguiente comando.

```powershell
$admin = 'admin@ixbalam.studio'
$project = 'clipforgebeta2'
$member = 'serviceAccount:clipforge-terraform-int@clipforgebeta2.iam.gserviceaccount.com'
$roles = 'projects/clipforgebeta2/roles'

& $gcloud iam roles describe clipforgeIntReadLogBucket_20261118T180000Z --project=$project --account=$admin --format='json(name,stage,deleted,includedPermissions)'
& $gcloud iam roles describe clipforgeIntReadSecretMetadata_20261118T180000Z --project=$project --account=$admin --format='json(name,stage,deleted,includedPermissions)'

# Mutaciones futuras, únicamente con el manifiesto exacto autorizado.
& $gcloud iam roles create clipforgeIntNobleIapRead_20261124T000000Z --project=$project --account=$admin --file="$bundle/role-iap.json" --quiet --format=none
& $gcloud projects add-iam-policy-binding $project --project=$project --account=$admin --member=$member --role="$roles/clipforgeIntReadLogBucket_20261118T180000Z" --condition-from-file="$bundle/condition-logbucket.json" --quiet --format=none
& $gcloud secrets add-iam-policy-binding clipforge-int-postgres-ca --project=$project --account=$admin --member=$member --role="$roles/clipforgeIntReadSecretMetadata_20261118T180000Z" --condition-from-file="$bundle/condition-ca.json" --quiet --format=none
& $gcloud secrets add-iam-policy-binding clipforge-int-bootstrap-admin --project=$project --account=$admin --member=$member --role="$roles/clipforgeIntReadSecretMetadata_20261118T180000Z" --condition-from-file="$bundle/condition-bootstrap.json" --quiet --format=none
```

La cuarta escritura usa el procedimiento `Invoke-IapBinding` del emisor histórico con la tupla de la fila `iap`. Hacer `POST https://iap.googleapis.com/v1/projects/816643438938/iap_tunnel/zones/us-central1-a/instances/1670495097211408131:getIamPolicy` con cuerpo `{"options":{"requestedPolicyVersion":3}}`. Exigir `etag` y que el rol/condición nuevos estén ausentes. Añadir un solo binding con `role` igual al rol IAP propuesto, `members` igual a una lista de un elemento con el principal Terraform y `condition` igual al contenido de `condition-iap.json`. Enviar `POST` a la misma ruta con sufijo `:setIamPolicy`, cuerpo `{"policy": ...}`, versión 3 y el `etag` leído. Releer y comprobar el cambio exacto y la preservación del binding funcional de Deploy. El administrador ejecuta ese Set con su autoridad existente. [Crear rol](https://docs.cloud.google.com/sdk/gcloud/reference/iam/roles/create) · [Binding proyecto](https://docs.cloud.google.com/sdk/gcloud/reference/projects/add-iam-policy-binding) · [Binding de secreto](https://docs.cloud.google.com/sdk/gcloud/reference/secrets/add-iam-policy-binding) · [API IAP](https://docs.cloud.google.com/iap/docs/reference/rest/v1/TopLevel/setIamPolicy)

La retirada usa `remove-iam-policy-binding` con los mismos argumentos de cada comando de proyecto/secreto. Para IAP, releer versión 3 y `etag`, retirar sólo el miembro del binding de condición/rol exactos y conservar cualquier otro miembro. Retirar la fila sólo si el recibo de grant o una lectura posterior acredita que está presente. Tras conflicto o resultado indeterminado, usar una sola lectura de comprobación de la tupla y detener escrituras hasta aclarar el resultado. La definición IAP queda inerte al retirar su último binding y cualquier eliminación de la definición requiere su propia decisión. No volver a conceder durante la retirada.

## Secuencia para validar y autorizar el siguiente plan

1. Consolidar el resultado de cada consulta independiente con la cuenta Terraform antes de firmar la selección. Reutilizar las lecturas fijas históricas y el IAP numérico. Conservar método, recurso, estatus, hora de cada operación y la identificación del run. La observación Noble usa WIF vigente y mantiene `int` manual, con entrega del token efímero al único paso de lecturas acotadas. IAP y Secret Manager documentan `cloud-platform` incluso para consultar sus políticas. El alcance de lectura procede de los métodos y endpoints fijados, y el permiso efectivo sigue sujeto a IAM. Un fallo de emisión se conserva como bloqueo de observación. [Lecturas históricas fijas](../scripts/int_iap_diagnostic.py) · [OAuth IAP](https://docs.cloud.google.com/iap/docs/reference/rest/v1/TopLevel/getIamPolicy#authorization-scopes) · [OAuth Secret Manager](https://docs.cloud.google.com/secret-manager/docs/reference/rest/v1/projects.secrets/getIamPolicy#authorization-scopes)
2. El administrador materializa únicamente la selección autorizada. Tras propagación, la misma identidad Terraform confirma el acceso a todos los endpoints requeridos, incluidos los que no recibieron grant. Una respuesta 403, 404, otro error o falta de recibo mantiene el bloqueo. Validar también generación, SHA, serial, direcciones y lock por sólo lectura con el comprobador de estado Noble. [Verificador de estado](../scripts/db01_noble_plan.py)
3. **Resolver antes del despacho la compatibilidad con la guarda de deriva.** Los grants de proyecto pueden modificar el `etag` de la policy que el provider 8.11.0 copia a `google_project_iam_audit_config.storage_access` y `google_project_iam_member.bootstrap_reader`. Los grants directos sobre secretos e IAP pueden cambiar los `etag` de sus respectivos miembros gestionados. El retiro anterior de IAP también pudo causar una diferencia que el run bloqueado aún no ha caracterizado. Comparar en memoria los `etag` actuales de las políticas afectadas con los atributos de los recursos exactos del estado fijado y conservar sólo el resultado booleano por dirección. El cierre anterior documentó deriva de este tipo a pesar de acciones `no-op`. El validador Noble exige `refresh_drift == {}`. Si hay divergencia, documentar el alcance y exigir una decisión separada y explícita para reconciliarlo mediante una verificación semántica completa. Esta propuesta mantiene vigente la guarda y el estado de fundación. [Cierre y clasificación históricos](../config/int-foundation-close.json) · [Provider 8.11.0, Read de audit config](https://raw.githubusercontent.com/hashicorp/terraform-provider-google/v8.11.0/google/tpgiamresource/resource_iam_audit_config.go) · [Provider 8.11.0, Read de IAM member](https://raw.githubusercontent.com/hashicorp/terraform-provider-google/v8.11.0/google/tpgiamresource/resource_iam_member.go)
4. Con lecturas verificadas, postcheck vigente, guarda satisfecha, ventana suficiente y revisión del SHA exacto, despachar una sola vez:

   ```powershell
   gh workflow run int-db01-noble-plan.yml --repo AldemaroCruz/ClipForge --ref ci/bootstrap-sec03 -f "approved_commit=$reviewedCommit"
   ```

   GitHub solicita aprobación manual de `int`. El único resultado aprobable para revisión de plan debe registrar salida nativa 2, 42 `no-op`, 11 creaciones, comprobaciones exigidas y los tres recibos de custodia. Un resultado bloqueado conserva el informe, el estado y la incertidumbre. Retirar el acceso READ conforme al paso de cierre sin programar otro intento.
