# DB-01 Noble · propuesta de creación y primera observación

**Estado de la decisión.** El paquete READ estable y la planificación Noble concluyeron. Esta preparación conserva sus recibos y deja pendientes los permisos de escritura que hagan falta, el apply y la primera observación. Fundación y GUEST-01 mantienen su cierre. [Plan exitoso](https://github.com/AldemaroCruz/ClipForge/actions/runs/44650537240) · [Resumen permitido y comprobación WIF](https://github.com/AldemaroCruz/ClipForge/actions/runs/44650537240/artifacts/14590397506) · [Paquete READ estable](DB-01-noble-read-package.md)

## Plan de origen y autoridad

| Dato | Valor fijado |
| --- | --- |
| Proyecto y ubicación | `clipforgebeta2` (`816643438938`), `us-central1-a`. |
| Productor y configuración | `c302dcc366ed450f91c1693072eb9008e7975e4c`, run `44650537240`, intento 1, Terraform 1.15.8 y proveedor Google 8.11.0. |
| Estado previo | Workspace `default`, `terraform/int/tf-int-01/default.tfstate`, generación `1795030868572779`, serial 7, lineage `813c84a2-2ef1-ceb3-177e-3a2c3b815066`, 110.325 bytes y SHA-256 `aa2d7bf8d15d0fe3fb8461483483be2aa49ccede18c94d67a1f5a5a723ef13ce`. El plan acreditó 42 direcciones. |
| Imagen | `ubuntu-os-cloud/ubuntu-2404-noble-amd64-v20261105`, ID `1892012953239034119`, familia `ubuntu-2404-lts-amd64`, READY, licencia estándar Ubuntu 24.04 LTS, X86_64. |
| Resultado y plazo | Código nativo de plan 2, once altas, 42 `no-op`. Vencimiento original `2026-11-21T01:05:19Z`, 20 de noviembre a las 19:05:19 de Guatemala. |
| Controles y aprobación | Un commit posterior de controles se vincula por SHA completo. El propietario identifica ese SHA, el productor, el plan exacto, las decisiones de seguridad y el delta IAM en una decisión explícita nueva. El manifiesto del plan conserva `apply_authorized: false`. |
| Ventana WRITE propuesta, pendiente | 20 de noviembre de 2026, 16:00–18:00 de Guatemala (`2026-11-20T22:00:00Z`–`2026-11-21T00:00:00Z`). Queda dentro del plazo del plan. Se requiere una nueva revisión si no se puede terminar la fase privilegiada dentro de la ventana. |

Los objetos se conservan bajo `gs://clipforgebeta2-tfstate-int/private-plans/int/c302dcc366ed450f91c1693072eb9008e7975e4c/`. Las referencias identifican originales de sólo lectura y se verifican por generación, bytes y SHA-256. [Recibo del run](https://github.com/AldemaroCruz/ClipForge/actions/runs/44650537240/artifacts/14590397506)

| Nombre relativo | Generación | Bytes | SHA-256 |
| --- | --- | ---: | --- |
| `44650537240-1/int.tfplan` | `1795136719332961` | 64.698 | `ce93b8dc52fc9ffddc91c30720f667d66752412aa6faf0ab2a347e8ddc49f8d6` |
| `44650537240-1/int.json` | `1795136719496104` | 403.117 | `ecd4973495e0a179b845787872038ef92e228425ec8421bf8f742674fb9741bd` |
| `44650537240-1/manifest.json` | `1795136719671258` | 10.100 | `6ca0f88d6345b2f77e3a28ace8c0cc8051544a23b259054f49ec24bdf2a9d4ff` |
| `44608046539-1/manifest.json` · recibo READ estable | `1795136476328109` | 43.427 | `e495bd6cca23fa19ecbd2c0ead3876273f4d9f797793d41afbea44475833af48` |

La [matriz WRITE consolidada](DB-01-noble-create-permissions.md) y su [alcance versionado](../config/int-db01-noble-write-iam.json) documentan autoridad existente, propuesta y comprobaciones pendientes. La decisión conserva las definiciones y políticas READ. Cualquier política que reciba permisos temporales deberá reconciliarse por versión, huella y lectura posterior, con el delta exacto como único cambio admitido.

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

El run informó nueve LOW y dos MEDIUM en la raíz que contiene Noble habilitado. Cuatro LOW corresponden a la candidata. La decisión del propietario debe identificar los cuatro por dirección y objeto. Debe optar por autorizar el diseño de cifrado predeterminado de Google para esa candidata y esa ventana, o exigir un diseño de claves de cliente y un nuevo plan. Las protecciones de borrado, red privada, cuenta dedicada y prohibición de datos reducen otras exposiciones. La custodia independiente, revocación y separación de acceso a claves de cliente seguirían pendientes. [Hallazgos del run](https://github.com/AldemaroCruz/ClipForge/actions/runs/44650537240/artifacts/14590397506) · [Cifrado de discos](https://docs.cloud.google.com/compute/docs/disks/disk-encryption)

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
| Ventana vencida o cambio material | Mantener íntegros referencias, objetos y evidencia. La renovación requiere una nueva decisión de planificación, preflight actual y un plan con nuevas referencias y plazo propio. Publicar los controles por sí solo mantiene el plan existente y su TTL original. |
| Apply parcial, error nativo, cancelación o recibo ausente | Mantener la intención, salida nativa y lecturas del backend. Preservar el estado y conciliar por GET las direcciones efectivas, candidatos observados, operación pendiente y cualquier lock. Cerrar como parcial o indeterminado hasta conciliarlo. La recuperación automática por reintento, unlock forzado, importación, reversión de infra o borrado queda fuera. |
| Apply completo | Registrar de forma separada la generación y huella posteriores, 53 direcciones, 42 preservadas e IDs de las once altas. Emitir el recibo de creación con los insumos mínimos para observar Noble. |
| Arranque o host key fallidos | Capturar sólo evidencia acotada y autenticada de Compute y del arranque. Una publicación truncada, repetida, ausente tras el plazo o ligada a otro arranque impide usar SSH. Una remediación, reinicio o canal alternativo requiere otra decisión. |
| Fallo de IAP/SSH, de retirada de clave, de disco o de inactividad PostgreSQL | Detener acciones posteriores, conservar la prueba del paso exacto y verificar por lectura los recursos y la entrada propia de OS Login. Terminar procesos propios y retirar sólo la clave pública creada cuando se pueda determinar el resultado. Mantener el TTL de seguridad y registrar resultados indeterminados. |
| SCA sin cobertura verificable o findings pendientes | Cerrar inventario y SCA en recibos separados. Conservar hallazgos y versiones observadas. Mantener activación y despliegue sujetos a decisiones posteriores. |

## Decisión única a presentar al propietario

La decisión operativa posterior debe vincular la huella del ZIP revisado, el SHA completo publicado de los controles, el productor `c302dcc366ed450f91c1693072eb9008e7975e4c`, los cuatro objetos de custodia, el vencimiento original, los cuatro hallazgos exactos de la candidata y el coste de coexistencia. Incluye el manifiesto WRITE y su huella, los permisos mínimos con actor, ámbito, precondiciones, ventana, verificación y retirada, y las referencias verificables de cada emisor. La autorización cubre un solo apply nativo protegido por `int` del binario fijado con locking, las once altas, el startup previsto y una primera observación Noble con pin estricto, limpieza de su clave y SCA del inventario real. Las autorizaciones extraordinarias previas conservan su alcance histórico.

La secuencia propuesta empieza con la conciliación de IAM y la aprobación manual de `int` para el [apply Noble](../.github/workflows/int-db01-noble-apply.yml). El [controlador](../scripts/int_noble_apply.py) valida fuentes y custodia con el SHA productor y fija aparte el SHA que ejecuta. Antes de Terraform registra una intención create-only en la ruta antes libre `44650537240-1/foundation-state.json` del prefijo original. La intención vincula el binario y el run de apply, y queda como evidencia si la ejecución se cancela. Una segunda reclamación se bloquea incluso desde otro SHA de controles. Los tres objetos originales del plan y el recibo READ conservan sus nombres y generaciones.

### Materialización posterior a la decisión

Los siguientes pasos son para la ejecución futura. El único mensaje de revisión del propietario debe identificar el SHA de controles, este plan exacto, el perfil WRITE y sus alcances efectivos, el coste y las cuatro decisiones IaC. De ese mensaje se derivan dos documentos privados con la misma referencia textual `owner_approval_ref`. Los archivos completos y el journal quedan fuera del repositorio.

- El primero se ajusta a `clipforge-db01-noble-write-authorization-1` y a la acción `authorize_exact_write_delta_for_noble_create_observe`. Sus demás campos son `owner_approval_ref`, `producer_commit`, `producer_run`, `controls_commit`, `profile_sha256` y `plan_manifest_sha256`. El operador verifica el estado anterior sin lock y ambas políticas antes de ejecutar el delta. [Operador WRITE](../scripts/int_noble_write_iam.py)
- El segundo se ajusta a `clipforge-db01-noble-create-observe-decision-1` y a la acción `exact_noble_creation_and_first_observation_authorized`. Incluye `owner_approval_ref`, `issued_utc`, `producer_commit`, `producer_run`, `controls_commit`, `project`, `plan` con las tres referencias completas, `expires_utc` exacto `2026-11-21T01:05:19.179283+00:00`, `write_profile_sha256`, `write_receipt`, `iac_findings_sha256` e `iac_decisions`. El hash de hallazgos fija las once filas originales en orden. Los índices nuevos **8, 9, 10 y 11** requieren filas individuales `finding_index`, `decision=reviewed_for_this_noble_creation` y `rationale` real. [Campos, huellas y guardas](../scripts/int_noble_apply.py)

Desde un checkout limpio del SHA publicado, el administrador usa los directorios privados y archivos obtenidos de esa autorización. `$ownerApply` sólo queda completo cuando existe la referencia del recibo WRITE verificado por el operador. Comprobar el código de salida y el recibo de cada comando antes de avanzar. Si un despacho queda indeterminado, consultar Actions por el SHA y conservar su resultado.

```powershell
$Profile = (python -B -m scripts.int_noble_write_iam describe | ConvertFrom-Json).profile_sha256
$Controls = (git rev-parse HEAD).Trim()
$Common = @('--controls-commit', $Controls, '--profile-sha256', $Profile)
python -B -m scripts.int_noble_write_iam preflight @Common --receipt-dir $privatePreflight
python -B -m scripts.int_noble_write_iam grant @Common --receipt-dir $privateJournal --approval $ownerWrite
python -B -m scripts.int_noble_write_iam publish-decision @Common --receipt-dir $privateJournal --approval $ownerWrite --decision $ownerApply
$OwnerRef = (Get-Content -Raw -LiteralPath (Join-Path $privateJournal 'owner-decision-reference.json')).Trim()
@{ approved_control_commit = $Controls; owner_decision = $OwnerRef } |
    ConvertTo-Json -Compress |
    gh workflow run int-db01-noble-apply.yml --repo AldemaroCruz/ClipForge --ref ci/bootstrap-sec03 --json
```

Tras el resultado de Terraform y la conciliación, retirar sólo los cuatro bindings temporales con `python -B -m scripts.int_noble_write_iam withdraw @Common --receipt-dir $privateJournal --approval $ownerWrite`. La retirada requiere las políticas esperadas y sus `etag` actuales. Si difieren, conservar evidencia y detener escrituras.

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
