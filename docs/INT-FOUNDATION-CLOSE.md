# Cierre de FUNDACIÃ“N INT: propuesta revisable

Grants sucesores, apply y retirada siguen pendientes de autorizaciÃ³n. Guest, host key, PostgreSQL, aplicaciÃ³n, Cloud Run y Jobs conservan sus etapas separadas.

## Plan y fuentes

Productor P: `24c753bd04cd3e530f08acee3768cb10545d1977`; [run 44360231461](https://github.com/AldemaroCruz/ClipForge/actions/runs/44360231461). Plan nativo completo y sin errores/diferidos: una creaciÃ³n `google_iap_tunnel_instance_iam_member.protected_bootstrap`, 41 `no-op`, cero updates/deletes/replacements/imports. Sink y VM son `no-op`; los cinco imports estÃ¡n completados.

ConfiguraciÃ³n SHA-256: `bf2a20357afc9ccd86edf34efd4a069ba7f43eb14b2853022ec031a9850fe0e1`. Terraform1.15.8, Google8.11.0, lock y startup permanecen fijados. El sink usa `unique_writer_identity=true` para representar igual que el Read del proveedor el writerIdentity vacÃ­o de la API. No afirma un escritor exclusivo. No hubo PATCH de prueba ni ignore_changes; destino/filtro/habilitaciÃ³n no cambian.

[Proveedor fijado](https://raw.githubusercontent.com/hashicorp/terraform-provider-google/67f96115b523ba050b11dad30237f14023667de8/google/services/logging/resource_logging_project_sink.go), [API](https://docs.cloud.google.com/logging/docs/reference/v2/rest/v2/projects.sinks#LogSink).

Se conservan las doce filas de refresh: diez cambios exclusivamente de etag y dos secretos con annotations/version_aliases exclusivamente nullâ†’{}. El clasificador compara keysets y valores completos restantes, exige igualdad integral con before/after del recurso `no-op`, y rechaza cualquier diferencia adicional, duplicado o import.

Backend: `gs://clipforgebeta2-tfstate-int/terraform/int/tf-int-01/default.tfstate`; generaciÃ³n1794975925421249, serial6, lineage813c84a2-2ef1-ceb3-177e-3a2c3b815066, SHA360a728e0e3dcb37050389b5bf936a4359107eeeb579794b96d35743a59a1f43. Son41direcciones. Los planes de serial1/5 y run44354702837 quedan histÃ³ricos.

Binario privado: generaciÃ³n1795023362274596, SHA9e6c6452ee4085533223e1adf0ce4c90d6319e1ceea131fa0af032df4dddac8e,45971bytes. Manifiesto privado: generaciÃ³n1795023362682797, SHAad7efc6f06ca2e7c9bad6e828f86bc184864585ddf7d6db0db5d8574ba733e38. Objetos bajo `private-plans/int/24c753bd04cd3e530f08acee3768cb10545d1977/44360231461-1/`. TTL hasta **19/11/2026 11:36:02.149542 de Guatemala**, sin extensiÃ³n. No se publica estado, planes completos ni bytes del manifiesto privado.

## Permisos de ejecuciÃ³n propuestos

Administrador: `admin@ixbalam.studio`. Principal de TODOS los grants: `serviceAccount:clipforge-terraform-int@clipforgebeta2.iam.gserviceaccount.com`.

Ventana fija propuesta: **18/11/2026 12:15 inclusivoâ€“14:15 exclusivo de Guatemala** (`18:15Zâ‰¤time<20:15Z`), dos horas. Los grants anteriores y sus vencimientos se conservan; entre12:00â€“12:15 no se afirma autoridad temporal nueva.

Manifiesto M: `2b26ef420a8534211f5760f45a20eeaad23b2ec79e44b25a2176bd3a1520589d`. Propuesta IAM: `13aa4f5ae778237b890dd02ae8f5c3f5364bfa13f857a5f0386d22d3744e67a1`. Se reutilizan ocho roles de lectura y el rol IAP existente, sin crear/editar/borrar definiciones: diez bindings de lectura mÃ¡s uno de gestiÃ³n IAP. La fecha del nombre de un rol no determina su caducidad.

T = request.timeâ‰¥18:15Z y <20:15Z del18/11/2026. B = T mÃ¡s tipo LogBucket y nombre exacto de `clipforge-int-access` enus-central1. V = T mÃ¡s tipo LogView y nombre exacto de `pilot-access` en ese bucket. Expresiones, tÃ­tulos, descripciones y hashes completos estÃ¡n en los tres JSON de condiciones.

| Binding ID | Existing custom role ID | Permission(s) | Policy resource | Condition |
| logging_bucket_read | clipforgeIntReadLogBucket_20261118T180000Z | logging.buckets.get | projects/clipforgebeta2 | B |
| secret_metadata_read_bootstrap_admin | clipforgeIntReadSecretMetadata_20261118T180000Z | secretmanager.secrets.get | projects/clipforgebeta2/secrets/clipforge-int-bootstrap-admin | T |
| secret_metadata_read_postgres_ca | clipforgeIntReadSecretMetadata_20261118T180000Z | secretmanager.secrets.get | projects/clipforgebeta2/secrets/clipforge-int-postgres-ca | T |
| postgres_sa_policy_read | clipforgeIntReadPostgresPolicy_20261118T180000Z | iam.serviceAccounts.getIamPolicy | projects/clipforgebeta2/serviceAccounts/clipforge-postgres-int@clipforgebeta2.iam.gserviceaccount.com | T |
| custom_role_metadata_read | clipforgeIntReadRoleMetadata_20261118T180000Z | iam.roles.get | projects/clipforgebeta2 | T |
| secret_policy_read_bootstrap_admin | clipforgeIntReadSecretPolicy_20261118T180000Z | secretmanager.secrets.getIamPolicy | projects/clipforgebeta2/secrets/clipforge-int-bootstrap-admin | T |
| secret_policy_read_postgres_ca | clipforgeIntReadSecretPolicy_20261118T180000Z | secretmanager.secrets.getIamPolicy | projects/clipforgebeta2/secrets/clipforge-int-postgres-ca | T |
| logging_sink_read | clipforgeIntReadLogSink_20261118T180000Z | logging.sinks.get | projects/clipforgebeta2 | T |
| logging_view_read | clipforgeIntReadLogView_20261118T180000Z | logging.views.get | projects/clipforgebeta2 | V |
| logging_view_policy_read | clipforgeIntReadLogViewPolicy_20261118T180000Z | logging.views.getIamPolicy | projects/clipforgebeta2/locations/us-central1/buckets/clipforge-int-access/views/pilot-access | T |
| iap_management | clipforgeIntRecoveryIapPolicy_20261118T044838Z | iap.tunnelInstances.getIamPolicy; iap.tunnelInstances.setIamPolicy | projects/816643438938/iap_tunnel/zones/us-central1-a/instances/1670495097211408131 | T |

Todos los roles estÃ¡n bajo `projects/clipforgebeta2/roles/`. Los Ã¡mbitos de proyecto de iam.roles.get y logging.sinks.get permiten consultar metadatos de otros nombres conocidos durante T, sin listar; esa amplitud queda a aprobaciÃ³n final. No hay payloads/versiones de secretos, Owner/Editor, actAs, tokens ni escritura de proyecto/Logging/secretos en el delta del pipeline.

setIamPolicy puede modificar toda la polÃ­tica IAP de la instancia exacta durante T, no sÃ³lo un miembro. El binario, la evidencia, las fuentes y las comprobaciones limitan su uso previsto; la condiciÃ³n IAM acota recurso/tiempo. DespuÃ©s se retira Ãºnicamente la nueva concesiÃ³n de gestiÃ³n a Terraform.

## Workflow y comandos preparados

`D` es el SHA completo del commit de controles identificado en la entrega. La configuraciÃ³n/plan permanecen enP; el workflow `.github/workflows/int-foundation-close.yml` hace checkout separado de ambos y verifica sus huellas. El aplicador histÃ³rico permanece cerrado. La evidencia nueva de fundaciÃ³nD incluye todas las fuentes del cierre y mantiene el gate de aplicaciÃ³n separado.

La decisiÃ³n entregada sigue `pending`. SÃ³lo despuÃ©s de autorizaciÃ³n expresa se cambian apply_decision y las decisiones residuales especÃ­ficas; despuÃ©s de los grants se completa exclusivamente el hash del Ã­ndice REAL de97recibos. No se alteran false/risk_pending histÃ³ricos. F-SAST-EXEC conserva visibles B404:16 y B603:169/180 de tf_int_plan.py SHA70982d2f5867d0101a181967d182058514e8c82a77423e5eceb09eb0cf89761b. F-VM-XML conserva imagen5913446147369107523/PGinactivo/sin datos/secretos/migraciones, sin afirmar inventario de guest. F-AUDIT sigue pendiente de validaciÃ³n operativa completa. LÃ­mite27/11/2026 23:59:59 de Guatemala; el apply de este paquete ademÃ¡s vence al terminarT.

Ejemplo PowerShell, Ãºnicamente despuÃ©s de la aprobaciÃ³n final. A es el SHA-256 de bytes de la nueva autorizaciÃ³n administrativa; R el del Ã­ndice real de97recibos. Archivos de decisiÃ³n y dispatch fuera del repositorio y del bundle cerrado:

```powershell
$bundle = '<ruta-extraida>\administrative-package'
$manifest = '2b26ef420a8534211f5760f45a20eeaad23b2ec79e44b25a2176bd3a1520589d'
python -B "$bundle\admin_close_grants.py" check --manifest-sha256 $manifest
python -B "$bundle\admin_close_grants.py" grant --manifest-sha256 $manifest --authorization-file '<autorizacion-administrativa-aprobada.json>' --authorization-sha256 '<A>'
python -B '<ruta-extraida>\execution-tools\prepare-close-dispatch.py' --repository 'C:\Users\itres\Desktop\clipforge-mvp' --controls-commit '<D-completo>' --decision-file '<decision-close-aprobada-con-R-real.json>' --foundation-report '<foundation-report-D.json>' --administrative-receipts "$bundle\receipts" --output '<temporal-privado>\close-dispatch.json'
gh api --method POST repos/AldemaroCruz/ClipForge/actions/workflows/int-foundation-close.yml/dispatches --input '<temporal-privado>\close-dispatch.json'
```

La autorizaciÃ³n administrativa se copia de owner-decision.template.json fuera del bundle y, sÃ³lo despuÃ©s de aprobaciÃ³n, tendrÃ¡ decision=`authorize_exact_foundation_close_bindings_and_management_withdrawal`, M exacto y los demÃ¡s campos originales. El preparador local sÃ³lo escribe un dispatch revisable; no crea aceptaciones ni llama a GitHub/GCP.

GitHub exigirÃ¡ la aprobaciÃ³n manual deint despuÃ©s del dispatch. No se elude. El workflow verifica otra vez WIF/ADC, estado6, generaciÃ³n/hash/lineage, imagen, custodia, TTL, versiones/lock, recibos y evidenciaD; aplica UNA vez el binario exacto con locking nativo, sin planificaciÃ³n implÃ­cita ni nuevos imports.

## Comprobaciones de cierre y retirada

1. Exigir Ã©xito del apply Y de las postverificaciones. Conservar run, recibo privado y resumen sanitizado; comprobar42direcciones sin taint, nueva generaciÃ³n/serial y mismo lineage.
2. Verificar miembro Deploy `roles/iap.tunnelResourceAccessor` sin condiciÃ³n en IAP numÃ©rico y preservaciÃ³n de los demÃ¡s bindings; VM RUNNING, identidad/arranque/metadata/IPprivada/red/discos/protecciones conservados; sink convergente sin afirmar escritor exclusivo ni auditorÃ­a completa. No SSH/guest ni PostgreSQL.
3. Dentro deT y sÃ³lo despuÃ©s de esos resultados, el administrador retira la concesiÃ³n de gestiÃ³n IAP. Antes comparar R con la decisiÃ³n y recibo de cierre:

```powershell
python -B "$bundle\admin_close_grants.py" withdraw-management --manifest-sha256 $manifest --authorization-file '<autorizacion-administrativa-aprobada.json>' --authorization-sha256 '<A>' --grant-receipt-index-sha256 '<R>'
```

La retirada conserva Deploy, los bindings anteriores y las diez lecturas. SÃ³lo retira el miembro Terraform de la nueva concesiÃ³n de gestiÃ³n IAP. Roles/bindings de lectura no se borran: sus condiciones dejan de otorgar autoridad al vencer. Guardar recibos de retirada separados. Ante fallo parcial, cambio de estado/condiciones/etag, expiraciÃ³n o postcheck fallido: detenerse y conservar evidencia; sin segundo apply, destroy, force-unlock, import ni restauraciÃ³n.

La decisiÃ³n concreta pendiente es aprobar plan/binarioP con controlesD, paqueteM/ventana, las decisiones residuales especÃ­ficas y retirada administrativa prevista. DespuÃ©s se requieren recibos reales y aprobaciÃ³n protegida deint. Esta entrega no ejecuta esas operaciones.
