# DB-01 Noble · propuesta de creación y primera observación

El run `44660649764` de `e5f4943ca6a67a257f8d09666abaad54822f1ee1` terminó en `blocked_preflight` con `noble_apply_write_window_unavailable` y `native_apply_attempted: false`. El flujo bajo demanda usa el perfil WRITE estable y verifica el estado real y las políticas antes de cualquier migración. Fundación y GUEST-01 mantienen su cierre. [Run anterior](https://github.com/AldemaroCruz/ClipForge/actions/runs/44660649764) · [Artefacto original del apply](https://github.com/AldemaroCruz/ClipForge/actions/runs/44660649764/artifacts/14604555083)

## Plan de origen y autoridad

| Dato | Valor fijado |
| --- | --- |
| Proyecto y ubicación | `clipforgebeta2` (`816643438938`), `us-central1-a`. |
| Productor y configuración | `c302dcc366ed450f91c1693072eb9008e7975e4c`, run `44650537240`, intento 1, Terraform 1.15.8 y proveedor Google 8.11.0. |
| Estado previo | Workspace `default`, `terraform/int/tf-int-01/default.tfstate`, generación `1795030868572779`, serial 7, lineage `813c84a2-2ef1-ceb3-177e-3a2c3b815066`, 110.325 bytes y SHA-256 `aa2d7bf8d15d0fe3fb8461483483be2aa49ccede18c94d67a1f5a5a723ef13ce`. El plan acreditó 42 direcciones. |
| Imagen | `ubuntu-os-cloud/ubuntu-2404-noble-amd64-v20261105`, ID `1892012953239034119`, familia `ubuntu-2404-lts-amd64`, READY, licencia estándar Ubuntu 24.04 LTS, X86_64. |
| Resultado y plazo | Código nativo de plan 2, once altas, 42 `no-op`. Vencimiento original `2026-11-21T01:05:19.179283+00:00`, 20 de noviembre de 2026 a las 19:05:19 de Guatemala. |
| Controles y aprobación | El SHA del ejecutor y el del productor se identifican por separado. Una decisión explícita vincula el plan exacto, su artefacto de revisión, las decisiones IaC y el recibo WRITE estable. El manifiesto de planificación conserva `apply_authorized: false`. |

Los objetos se conservan bajo `gs://clipforgebeta2-tfstate-int/private-plans/int/c302dcc366ed450f91c1693072eb9008e7975e4c/`. Las referencias identifican originales de sólo lectura y se verifican por generación, bytes y SHA-256. [Recibo del run](https://github.com/AldemaroCruz/ClipForge/actions/runs/44650537240/artifacts/14590397506)

| Nombre relativo | Generación | Bytes | SHA-256 |
| --- | --- | ---: | --- |
| `44650537240-1/int.tfplan` | `1795136719332961` | 64.698 | `ce93b8dc52fc9ffddc91c30720f667d66752412aa6faf0ab2a347e8ddc49f8d6` |
| `44650537240-1/int.json` | `1795136719496104` | 403.117 | `ecd4973495e0a179b845787872038ef92e228425ec8421bf8f742674fb9741bd` |
| `44650537240-1/manifest.json` | `1795136719671258` | 10.100 | `6ca0f88d6345b2f77e3a28ace8c0cc8051544a23b259054f49ec24bdf2a9d4ff` |
| `44608046539-1/manifest.json` · recibo READ estable | `1795136476328109` | 43.427 | `e495bd6cca23fa19ecbd2c0ead3876273f4d9f797793d41afbea44475833af48` |

La matriz WRITE documenta el alcance vigente de los cuatro bindings y la cadena de recibos hasta las políticas efectivas. [Matriz WRITE](DB-01-noble-create-permissions.md) · [Perfil versionado](../config/int-db01-noble-write-iam.json)

## Once altas y conservación de Debian

| Dirección en el plan | Efecto y comprobación posterior |
| --- | --- |
| `google_service_account.noble[0]` | Cuenta dedicada `clipforge-db01-noble-int@clipforgebeta2.iam.gserviceaccount.com` para la VM y los firewalls que la seleccionan. |
| `google_compute_address.noble[0]` | IP privada reservada `10.80.1.3` en la subred PostgreSQL `10.80.1.0/28`. |
| `google_compute_disk.noble_boot[0]` | `clipforge-int-db01-noble-boot`, 10 GiB `pd-standard`, con el ID de imagen fijado. |
| `google_compute_disk.noble_data[0]` | `clipforge-int-db01-noble-data`, 20 GiB `pd-standard`, creado sin imagen, snapshot ni disco fuente. |
| `google_compute_firewall.noble_iap[0]` | Entrada TCP/22 desde IAP `35.235.240.0/20` con destino a la cuenta Noble. |
| `google_compute_firewall.noble_https[0]` | Salida TCP/443 de mantenimiento para la cuenta Noble por la red y NAT existentes. |
| `google_compute_firewall.noble_deny_egress[0]` | Denegación de las demás salidas según prioridad explícita y registro de tráfico del plan. |
| `google_compute_instance.noble[0]` | `clipforge-int-db01-noble`, `e2-small`, interfaz IPv4 privada, sin IP pública y con `userinfo.email` como scope. Shielded VM con Secure Boot, vTPM y monitoreo de integridad. Protección de borrado y `prevent_destroy`; discos con `autoDelete=false` verificado. |
| `google_compute_instance_iam_member.noble_deploy[0]` | `roles/compute.osAdminLogin` sólo para Deploy en la VM nueva. |
| `google_iap_tunnel_instance_iam_member.noble_deploy[0]` | `roles/iap.tunnelResourceAccessor` sólo para Deploy, limitado a TCP/22 en el ID numérico real de la VM nueva. |
| `google_service_account_iam_member.noble_deploy[0]` | `roles/iam.serviceAccountUser` sólo para Deploy en la SA Noble. El `actAs` que necesita Terraform se resuelve en la matriz WRITE. |

Un apply completo debe registrar **53 direcciones** y conservar la generación previa como evidencia, el lineage original y las 42 direcciones base. La verificación distingue las once altas de las once transiciones READ de `etag` ya verificadas por el productor. Conserva la VM Debian ID `1670495097211408131`, IP `10.80.1.2`, boot ID `2158164599035219715`, datos ID `6427691858848206684` y sus bindings. Los IDs de Noble se obtienen del estado posterior y se cotejan con Compute. [HCL que produjo el plan](https://github.com/AldemaroCruz/ClipForge/blob/c302dcc366ed450f91c1693072eb9008e7975e4c/infra/gcp/int-base/noble-candidate.tf) · [Identidad Debian fijada](../config/int-foundation-verification.json)

## Efectos del startup y postchecks

1. El startup comprueba plataforma Ubuntu 24.04 LTS Noble amd64, espera acotadamente a cloud-init y exige APT y `libapt-pkg6.0t64` al menos en `2.8.4ubuntu0.1`. Usa TLS verificado, hashes del keyring Ubuntu y clave PGDG, metadatos APT firmados, resolución acotada sin removals ni downgrades, hashes de los archivos Debian y comprobación posterior de versiones y binarios. El repositorio PGDG usa `noble-pgdg` para el conjunto revisado. [Startup fijado](https://github.com/AldemaroCruz/ClipForge/blob/c302dcc366ed450f91c1693072eb9008e7975e4c/infra/gcp/int-base/db01-noble-startup.sh)
2. Antes de instalar, deja `create_main_cluster = false`, enmascara `postgresql.service` y `postgresql@.service` y usa su propio `policy-rc.d` temporal para prevenir arranques durante la instalación. Fija `postgresql-17` y `postgresql-client-17` en `17.12-1.pgdg24.04+1`, `postgresql-common` y `postgresql-client-common` en `297.pgdg24.04+1`, `libpq5` en `18.7-1.pgdg24.04+2` y `libxml2` en `2.9.14+dfsg-1.3ubuntu3.10`. Un marcador durable bloquea una instalación parcial. La terminación válida verifica máscaras, ausencia de clústeres, rutas inicializadas, procesos y listeners, y conserva el recibo de procedencia en el disco de arranque. El disco de datos queda intacto.
3. Sólo tras una primera instalación válida, el publicador revisado espera acotadamente la clave de host pública Ed25519 y emite un registro serial. Lo vincula con proyecto, zona, nombre e ID numérico de la instancia, `boot_id`, nonce derivado del startup fijado y hashes del publicador y sus dependencias. La lectura autenticada de la salida serial usa la API con `start=0` y límites de tamaño, entre dos GET concordantes de Compute. La consola serial interactiva permanece deshabilitada. La publicación fallida conserva su propio diagnóstico y bloquea el pin. [Publicador](../scripts/int_noble_hostkey.py) · [Salida serial por API](https://docs.cloud.google.com/compute/docs/troubleshooting/troubleshooting-using-serial-console)
4. El postcheck contrasta estado y API para nombre e ID, imagen, `10.80.1.3`, cuenta, tipo de VM, timestamp de creación y primer arranque, metadatos y su huella, protecciones, discos y bindings. Ambos discos tienen adjunto exclusivo, tipo y tamaño esperados, protecciones y sin autoeliminación. Se verifican las tres políticas sobre los recursos recién materializados. Se comprueban la red y los firewalls con la topología planeada. Una observación desde otro arranque requiere otra decisión.
5. Con el pin verificado, Deploy abre un único túnel IAP hacia el puerto 22 del ID nuevo. Si hace falta una clave de acceso, registra únicamente la clave pública efímera del run en su perfil OS Login, con TTL de 900 segundos, y verifica su retirada. SSH usa `known_hosts` fijado por clave Ed25519 e ID exacto, comprobación estricta, identidad explícita y sin mecanismos alternativos. El comando remoto fijo ejecuta el payload de sólo lectura revisado con límites de 120 segundos y 2 MiB. Se cotejan identidad y primer arranque antes y después de la sesión.
6. La sonda registra distribución, arquitectura y kernel activos, inventario binario y fuente de dpkg y versiones PostgreSQL. Contrasta las versiones con las seis fijadas para el startup, incluidas las revisiones PGDG. Vincula el ID del disco de datos de Compute con el adjunto SCSI índice 1 y `/dev/disk/by-id/google-clipforge-noble-pg-data`, serial concordante en sysfs, lsblk y udev, dispositivo y `major:minor`. Exige disco distinto de raíz, sin holders, particiones, firmas, mounts o datos inesperados. PostgreSQL debe permanecer enmascarado e inactivo, sin clústeres, procesos, TCP/5432 ni sockets Unix. Cualquier incumplimiento bloquea la fase y conserva el hallazgo. [Validador de Compute, arranque e inventario](../scripts/int_noble_guest_observation.py) · [Transporte histórico reutilizado](../scripts/int_guest_inventory.py)

## SCA del guest real

Tras una observación válida, Seguridad revisará el inventario capturado de esta VM. El análisis fuera del guest se liga a SHA-256 de la evidencia, IDs de VM y discos, `boot_id`, commits y resultado del pin. El insumo incluirá nombre de binario y fuente exactos, versiones con epoch y revisión, arquitectura y estado dpkg observado. Deben cuadrar los paquetes instalados y la lista enviada al scanner. Los estados no instalados o incompletos se declaran aparte. El kernel activo se correlaciona con sus paquetes de imagen y módulos, variante de Ubuntu/GCE, versión de fuente y avisos de Canonical.

Se conservarán SBOM, identificación por versión y digest del scanner, versión/fecha/huella de la base utilizada, informe nativo y cobertura por componente. El perfil de Ubuntu y PGDG debe conservar la familia Noble al normalizar sin alterar versiones. Para `postgresql-17`, `libpq5` y las demás fuentes PGDG se contrastan también los avisos de PostgreSQL, porque la fuente Ubuntu de Trivy sólo cubre los avisos del distribuidor. Se comprobará en los paquetes observados la corrección de `libxml2` de Canonical. Clasificar por separado las filas del scanner, los avisos que dependen de la fuente, la cobertura del kernel y las bibliotecas fuera del inventario.

El alcance de SCA de este paso abarca metadatos de paquetes y la correlación del kernel activo. Bibliotecas vendorizadas, binarios fuera de dpkg, archivos del guest y el cliente OCI requieren cobertura propia. La evaluación local Ubuntu y la observación histórica de Debian conservan su evidencia y el expediente de esta VM quedará abierto hasta recibir su inventario real. [Cobertura Trivy en Ubuntu](https://trivy.dev/docs/latest/guide/coverage/os/ubuntu/) · [Avisos de PostgreSQL](https://www.postgresql.org/support/security/) · [Aviso Canonical para libxml2](https://ubuntu.com/security/notices/USN-8456-1)

## Hallazgos IaC para esta decisión

El run informó nueve LOW y dos MEDIUM en la raíz que contiene Noble habilitado. Cuatro LOW corresponden a la candidata. La decisión del propietario debe identificar los cuatro por dirección y objeto. Debe optar por autorizar el diseño de cifrado predeterminado de Google para la candidata del plan elegido o exigir un diseño de claves de cliente y un nuevo plan. Las protecciones de borrado, red privada, cuenta dedicada y prohibición de datos reducen otras exposiciones. La custodia independiente, revocación y separación de acceso a claves de cliente seguirían pendientes. [Hallazgos del run](https://github.com/AldemaroCruz/ClipForge/actions/runs/44650537240/artifacts/14590397506) · [Cifrado de discos](https://docs.cloud.google.com/compute/docs/disks/disk-encryption)

| ID | Severidad | Instancia del hallazgo | Decisión pendiente |
| --- | --- | --- | --- |
| `GCP-0033` | LOW | `google_compute_instance.noble[0]`, bloque `boot_disk`, líneas 174–178 | Revisar el cifrado predeterminado en el arranque de Noble. |
| `GCP-0033` | LOW | `google_compute_instance.noble[0]`, bloque `attached_disk`, líneas 179–182 | Revisar el cifrado predeterminado del adjunto de datos vacío. |
| `GCP-0034` | LOW | `google_compute_disk.noble_boot[0]`, líneas 87–104 | Revisar la falta de CMEK para el disco boot independiente. |
| `GCP-0034` | LOW | `google_compute_disk.noble_data[0]`, líneas 106–116 | Revisar la falta de CMEK para el disco de datos independiente. |

Las siete filas de recursos preservados siguen visibles. Son dos `GCP-0033` de la VM Debian, un `GCP-0034` de su disco y dos `GCP-0066` y dos `GCP-0077` de media y backups. Los MEDIUM corresponden al criterio de access logging del bucket. Cloud Audit Logs es un control separado. Las decisiones de Fundación conservan sus condiciones y alcance histórico. La creación aislada usa la evidencia IaC del productor, la revisión individual de los cuatro hallazgos y las pruebas dirigidas de controles. El CI de aplicación y los gates SAST/SCA de runtime, release y despliegue conservan su efecto y alcance propios. [Decisiones exactas de Fundación](../config/owner-risk-acceptance.json) · [Diseño de Logging y límites](../config/int-e2e01-decisions.json) · [Separación de fases](INT-FOUNDATION-APPLY-AUTHORIZATION.md)

## Coste incremental y coexistencia

Estimación del modelo versionado en USD para siete días continuos, 168 horas, en `us-central1`. Asume Debian `e2-micro`, Noble `e2-small`, 30 GiB de `pd-standard` por VM, un GiB procesado por NAT y 0,1 GiB de egreso por VM, 0,25 GiB de logs de red y 0,1 GiB de otros logs por VM, una IPv4 compartida de NAT y almacenamiento marginal de planes de 0,1 GiB. La base Debian presupone 20,1 GiB de almacenamiento existente. Usa 730 h/mes para prorratear y tarifas de lista sin descuentos ni cupos gratuitos. Las tarifas, operaciones y volúmenes asumidos se revisan contra la facturación real. [Modelo versionado](../config/tf-int01-costs.json) · [VM](https://cloud.google.com/products/compute/pricing/general-purpose?hl=en) · [Discos](https://cloud.google.com/compute/disks-image-pricing) · [NAT](https://cloud.google.com/nat/pricing) · [Logging](https://cloud.google.com/products/observability/pricing) · [GCS](https://cloud.google.com/storage/pricing)

| Concepto | Debian base USD | Incremento Noble USD |
| --- | ---: | ---: |
| VM | 1,4072 | 2,8145 |
| Boot y datos | 0,2762 | 0,2762 |
| NAT por VM, tráfico y egreso | 0,2922 | 0,2922 |
| IPv4 compartida de NAT | 0,8400 | 0,0000 |
| Logs | 0,1750 | 0,1750 |
| Storage y operaciones | 0,0979 | 0,0059 |
| **Subtotal** | **3,09** | **3,56** |

Coexistencia estimada **USD 6,65**. Si NAT asigna una IPv4 adicional durante siete días, el incremento sube a USD 4,40 y la coexistencia a **USD 7,49**. El modelo excluye impuestos y variaciones de tráfico, logging, operaciones o retención que excedan sus supuestos. El propietario revisaría la convivencia al séptimo día y decidiría la retención de la VM y ambos discos. Un estado parcial puede facturar recursos creados aunque la observación quede bloqueada.

## Cierre operativo y fallos

| Resultado | Respuesta prevista |
| --- | --- |
| Permiso, presupuesto, huella, estado o plazo discrepante antes del apply | Detener el runner antes de invocar Terraform y conservar el diagnóstico. Diferenciar permiso observado, soporte documentado y permiso efectivo futuro sobre la nueva identidad. Conciliar las políticas previas, el delta WRITE autorizado y las políticas resultantes, preservando el recibo READ original. |
| Plan vencido o cambio material | Mantener íntegros referencias, objetos y evidencia. Generar un plan con referencias propias, preflight actual y comparación de alcance, imagen y hallazgos antes de aprobarlo. El recibo WRITE estable se reutiliza previa comprobación de las políticas. |
| Apply parcial, error nativo, cancelación o recibo ausente | Mantener la intención, salida nativa y lecturas del backend. Preservar el estado y conciliar por GET las direcciones efectivas, candidatos observados, operación pendiente y cualquier lock. Cerrar como parcial o indeterminado hasta conciliarlo. La recuperación automática por reintento, unlock forzado, importación, reversión de infra o borrado queda fuera. |
| Apply completo | Registrar de forma separada la generación y huella posteriores, 53 direcciones, 42 preservadas e IDs de las once altas. Emitir el recibo de creación con los insumos mínimos para observar Noble. |
| Arranque o host key fallidos | Capturar sólo evidencia acotada y autenticada de Compute y del arranque. Una publicación truncada, repetida, ausente tras el plazo o ligada a otro arranque impide usar SSH. Una remediación, reinicio o canal alternativo requiere otra decisión. |
| Fallo de IAP/SSH, de retirada de clave, de disco o de inactividad PostgreSQL | Detener acciones posteriores, conservar la prueba del paso exacto y verificar por lectura los recursos y la entrada propia de OS Login. Terminar procesos propios y retirar sólo la clave pública creada cuando se pueda determinar el resultado. Mantener el TTL de seguridad y registrar resultados indeterminados. |
| SCA sin cobertura verificable o findings pendientes | Cerrar inventario y SCA en recibos separados. Conservar hallazgos y versiones observadas. Mantener activación y despliegue sujetos a decisiones posteriores. |

## Decisión del plan y primera observación

La decisión operativa vincula los SHA del productor y de los controles, el run e intento del productor, el ID y la huella del artefacto de revisión, las tres referencias privadas, el vencimiento del plan, el recibo WRITE estable y las decisiones IaC individuales. El coste de coexistencia se revisa para el plan elegido. [Matriz WRITE](DB-01-noble-create-permissions.md)

**Cuatro decisiones IaC individuales.** Cada fila requiere la decisión `reviewed_for_this_noble_creation` y su propia justificación. Los índices 8 a 11 se toman del orden fijado en los hallazgos del productor.

| Hallazgo | Recurso y decisión pendiente |
| --- | --- |
| `GCP-0033` | Cifrado predeterminado del bloque `boot_disk` de `google_compute_instance.noble[0]`. |
| `GCP-0033` | Cifrado predeterminado del bloque `attached_disk` de `google_compute_instance.noble[0]`. |
| `GCP-0034` | Ausencia de CMEK en `google_compute_disk.noble_boot[0]`. |
| `GCP-0034` | Ausencia de CMEK en `google_compute_disk.noble_data[0]`. |

**Ejecución y comprobaciones propuestas.** La decisión debe cubrir los siguientes pasos con recibos diferenciados.

1. Aplicar una sola vez el binario aprobado, con aprobación manual de `int` y locking nativo. El binario fija once altas, 42 `no-op` y el startup previsto. Conciliar estado y postchecks antes de continuar.
2. Verificar las políticas WRITE y READ completas y los tres bindings de Deploy creados por el binario. El delta WRITE estable queda disponible para el flujo protegido.
3. Observar por primera vez el guest nuevo con Deploy por WIF, IAP al puerto 22 y pin estricto de la clave de host. Retirar la clave pública efímera propia de OS Login y verificar su ausencia. Su TTL es de 900 segundos.
4. Verificar y conservar el inventario del guest observado, incluidos los paquetes binarios y fuente, el kernel activo, el disco de datos vacío y PostgreSQL inactivo. Ligar el recibo al ID de VM, discos y primer arranque.
5. Escanear fuera del guest el SBOM de ese inventario con Trivy y una base identificada. Conservar el informe nativo, la cobertura y las huellas del scanner, la base y sus insumos.
6. Revisar los resultados del scan y su cobertura por componente. Contrastar los avisos de Canonical y PGDG con las versiones observadas, comprobar la aplicabilidad al kernel activo y documentar las brechas pendientes.

El controlador valida fuentes y custodia del productor y fija aparte el SHA que ejecuta. Antes de Terraform registra una intención create-only de la creación Noble en la ruta reservada `44650537240-1/foundation-state.json`. La intención vincula el binario elegido y el run de apply. Una segunda reclamación de la creación se bloquea aunque use otro plan o SHA de controles. [Controlador](../scripts/int_noble_apply.py)

### Migración administrativa única

El administrador usa un checkout limpio del SHA publicado y un journal privado fuera del repositorio. La autorización `clipforge-db01-noble-stable-write-authorization-1` identifica la acción `replace_exact_temporal_noble_write_with_stable`, `owner_approval_ref`, `controls_commit`, `profile_sha256` y la referencia completa `temporary_receipt`. El preflight comprueba lock, estado y políticas. Un fallo parcial se concilia a partir de las intenciones y las políticas completas del mismo journal. La revocación deliberada usa una autorización propia y los `etag` vigentes. [Operador WRITE](../scripts/int_noble_write_iam.py)

```powershell
$Profile = (python -B -m scripts.int_noble_write_iam describe | ConvertFrom-Json).profile_sha256
$Controls = (git rev-parse HEAD).Trim()
$Common = @('--controls-commit', $Controls, '--profile-sha256', $Profile)
python -B -m scripts.int_noble_write_iam preflight @Common --receipt-dir $privateJournal
python -B -m scripts.int_noble_write_iam migrate @Common --receipt-dir $privateJournal --approval $ownerWrite
```

`stable-receipt-reference.json` identifica la instalación que se reutiliza al planificar y aplicar. Para revocarla de forma deliberada, usar `revoke` con la acción `revoke_exact_stable_noble_write`, campo `stable_receipt` y journal de revocación independiente. Para revertir una migración parcial, usar `revoke-partial --source-journal` con el journal original, la acción `revoke_exact_partial_noble_write` y los campos `temporary_receipt` y `migration_controls_commit`. Ambas operaciones cotejan el estado vivo antes de tocar políticas. [Contrato de revocación](../scripts/int_noble_write_iam.py)

### Solicitar un plan y aprobar su apply

1. Usar el plan original mientras siga vigente y el backend y sus fuentes coincidan. Para renovar, despachar `int-db01-noble-plan.yml` desde `ci/bootstrap-sec03` con `approved_commit` y `stable_write_receipt`, el JSON del recibo inmutable de cuatro campos.
2. Revisar el run de planificación exitoso, el artefacto permitido y el resumen de sus acciones. Si es un plan nuevo, comparar imagen, estado, direcciones y hallazgos con el original. Las justificaciones IaC pertenecen al artefacto revisado.
3. Preparar la decisión privada `clipforge-db01-noble-create-observe-decision-2` con acción `exact_noble_creation_and_first_observation_authorized`. Incluye `owner_approval_ref`, `issued_utc`, `producer_commit`, `producer_run`, `controls_commit`, `project`, `plan` con referencias `binary`, `json` y `manifest`, `expires_utc`, `plan_artifact` con `id` y `sha256`, `write_profile_sha256`, `write_receipt`, `iac_findings_sha256` e `iac_decisions` con una justificación para cada hallazgo aplicable.
4. Publicar la decisión verificada en custodia privada, despachar el apply con las referencias seleccionadas y revisar esos datos al aprobar `int`. Ante respuesta de despacho indeterminada, consultar los runs de Actions por SHA y workflow.

```powershell
python -B -m scripts.int_noble_apply publish-decision --controls $Controls --decision $ownerApply --output $ownerRefFile
$OwnerRef = (Get-Content -Raw -LiteralPath $ownerRefFile).Trim()
@{ approved_control_commit = $Controls; owner_decision = $OwnerRef;
   producer_commit = $Producer; producer_run = $PlanRun; plan_manifest = $PlanManifest;
   plan_artifact_id = $ArtifactId; plan_artifact_sha256 = $ArtifactSha256 } |
    ConvertTo-Json -Compress |
    gh workflow run int-db01-noble-apply.yml --repo AldemaroCruz/ClipForge --ref ci/bootstrap-sec03 --json
```

El resumen exitoso identifica el run y la referencia del objeto privado de creación. El lector autorizado verifica su procedencia y obtiene el pin autenticado del primer arranque. El archivo contiene únicamente la identidad y la clave pública válidas para esa observación. `$ApplySummaryHash` y `$HostPinHash` son las huellas de bytes exactos de los archivos verificados.

```powershell
python -B -m scripts.int_noble_first_observation pin --apply-summary $ApplySummary --summary-sha256 $ApplySummaryHash --controls $Controls --apply-run $ApplyRun --output $HostPin
$PinInput = Get-Content -Raw -LiteralPath $HostPin
@{ approved_control_commit = $Controls; apply_run_id = $ApplyRun; apply_summary_sha256 = $ApplySummaryHash;
   host_pin_json = $PinInput; host_pin_sha256 = $HostPinHash } |
    ConvertTo-Json -Compress |
    gh workflow run int-db01-noble-observe.yml --repo AldemaroCruz/ClipForge --ref ci/bootstrap-sec03 --json
```

El inventario exitoso produce `noble.cdx.json` y `sca-input.json`. Desde un directorio aislado, preparar una base Trivy separada y fijar el digest de la imagen `ghcr.io/aquasecurity/trivy:0.76.2@sha256:6fa071ef8daa2e58b90cbf1710bedca91adbb3bf98693533226f442035b836a6`. Conservar el digest de `trivy.db` y `metadata.json`, ejecutar `trivy sbom --skip-db-update --offline-scan --scanners vuln --list-all-pkgs --format json noble.cdx.json` sin red sobre esos insumos, y pasar los archivos exactos a `python -B -m scripts.int_noble_first_observation verify-sca` con `--inventory`, `--inventory-sha256`, `--native-report`, `--db`, `--db-sha256`, `--db-metadata` y `--output`. Los avisos PGDG y la aplicabilidad del kernel se revisan aparte sobre las versiones observadas. [Control de cobertura de SCA](../scripts/int_noble_first_observation.py)

La primera [observación Noble](../.github/workflows/int-db01-noble-observe.yml) valida el run de apply exitoso, el resumen exacto y el hash del pin antes de usar WIF Deploy. Conserva su aprobación manual de `int`. El cierre registra de forma independiente el resultado Terraform, la conciliación del estado, el arranque, el pin, la observación y la revisión de seguridad. Bootstrap PostgreSQL, montajes y formato del disco, SQL, TLS, secretos, clientes, release y despliegue requieren decisiones independientes.
