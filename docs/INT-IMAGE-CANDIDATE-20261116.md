# Candidata Debian 13 del 16 de noviembre para fundación

Revisión de solo lectura: **2026-11-17, 22:29 UTC**. Se ejecutaron dos
`gcloud compute images describe` sobre el proyecto público `debian-cloud`, con
la autenticación local habitual autorizada. Ambos GET terminaron con código 0.
No se creó VM, disco, imagen ni otro recurso; no hubo apply, inventario de VM,
scanner, cambios IAM, de startup o de workflow.

## Cambio concreto de imagen

| Metadato | Referencia anterior | Candidata |
| --- | --- | --- |
| Nombre | `debian-13-trixie-v20261109` | `debian-13-trixie-v20261116` |
| ID numérico | `5399869132233489518` | **`5913446147369107523`** |
| Creación declarada | `2026-11-09T09:27:30.333-08:00` | `2026-11-16T09:34:37.318-08:00` |
| Estado | `READY` | `READY` |
| Deprecación | `DEPRECATED`; replacement apunta exactamente a la candidata | Campo `deprecated` ausente en la respuesta GET |
| Proyecto / familia | `debian-cloud` / `debian-13` | Iguales |
| SO declarado | Debian GNU/Linux 13 (trixie), amd64 | Igual; cambia la fecha de build |
| Arquitectura | `X86_64` | Igual |
| Tamaño de imagen declarado, `diskSizeGb` | 10 | Igual |
| `archiveSizeBytes` informado por la API | 36.553.715.200 | 36.610.060.800 |
| Licencia | `projects/debian-cloud/global/licenses/debian-13-trixie` | Igual |
| Tipo de fuente | `RAW` | Igual |
| `enableConfidentialCompute` | `false` | Igual |
| Guest features y ubicaciones de almacenamiento | Conjuntos comparados | Iguales, incluido `us-central1` |

SelfLinks exactos:

- Anterior: `https://www.googleapis.com/compute/v1/projects/debian-cloud/global/images/debian-13-trixie-v20261109`.
- Candidata: `https://www.googleapis.com/compute/v1/projects/debian-cloud/global/images/debian-13-trixie-v20261116`.

Guest features coincidentes: `UEFI_COMPATIBLE`, `VIRTIO_SCSI_MULTIQUEUE`, `GVNIC`,
`SEV_CAPABLE`, `SEV_SNP_CAPABLE`, `SEV_LIVE_MIGRATABLE_V2`, `IDPF` y
`SUSPEND_SAFE_FPR`. Su presencia no prueba que todas se habiliten en la futura VM.
`archiveSizeBytes` es otro metadato que cambia; no se usa como inventario de
contenido ni para sustituir el tamaño de disco declarado de 10 GB.

La [documentación oficial de Google sobre Debian](https://docs.cloud.google.com/compute/docs/images/os-details#debian)
identifica Debian 13 x86 como familia `debian-13` del proyecto `debian-cloud`,
con licencia gratuita `debian-13-trixie`. La procedencia de ambos recursos es
coherente con ese catálogo público; no se deriva de ello igualdad de paquetes ni
ausencia de vulnerabilidades. Se revisa una versión exacta, no la familia móvil.

## Compatibilidad estática y límites

El startup revisado `infra/gcp/int-base/postgres-install.sh` conserva SHA-256
`a93bd662abce93b12c6389a37fccca49612ef3d1ee83eb882051cd5489daf255`. Exige
`ID=debian`, `VERSION_CODENAME=trixie` y keyring Debian; usa APT firmado con
trixie, updates y security. La identidad y arquitectura declaradas de la
candidata son compatibles con esos requisitos y con el boot previsto de 10 GB.
No se ha comprobado el filesystem real, la ejecución del guion, disponibilidad
de e2-micro ni el resultado de resolver todas las dependencias.

Se reutiliza la consulta oficial de **2026-11-17, 19:43 UTC**, con antigüedad
inferior a cuatro horas: PG y cliente `17.12-0+deb13u1` publicados para
trixie-security, ambos `.deb` exactos con HEAD 200. No se repitió esa consulta.
Fuentes: [servidor](https://packages.debian.org/trixie/postgresql-17) y
[cliente](https://packages.debian.org/trixie/postgresql-client-17).

El guion mantiene `create_main_cluster = false` y servicios PostgreSQL masked;
no inicializa disco/clúster, no crea roles, no ejecuta SQL ni carga secretos.
Son controles previstos, todavía no resultados operativos. No se encontró una
incompatibilidad estática que exija ampliar el incremento; esto permite revisar
la candidata en el nuevo plan, **no autoriza apply ni habilitar PostgreSQL**.

**F-VM-XML para esta candidata: `risk_pending`.** La aceptación vinculada a la
base anterior no se traslada automáticamente al ID nuevo. La dependencia
esperada de libxml2 y su condición conocida siguen visibles; el inventario,
SCA y alcanzabilidad reales de la futura VM no existen. Tampoco se le atribuyen
resultados de imágenes PostgreSQL de CI, PyAV o del runtime multimedia. Cualquier
decisión específica del propietario debe identificar esta candidata y sus
condiciones; no extiende el TTL del plan ni habilita bootstrap/secretos/servicio.

## Evidencia conservada

Las respuestas completas, stderr, recibos GET y comparación permanecen fuera
del repositorio, en
`C:\Users\itres\AppData\Local\ClipForge\foundation-renewal\attempt-a8a36147da54411dbbcb19c227e9facd\image-candidate-review`.
SHA-256 de las respuestas guardadas: anterior
`f3d4278a03567b090a845cc0f9503b9c50c92eadb48d8db2b18f9cd73fce309f`;
candidata `db091c2a0698b57b0d89c03582af4ca5734330a6145460c3406effa75d4e3fc7`.
La evidencia Debian reutilizada está en el intento hermano
`debian-20261117T194313Z-26fed9a23149/summary.json`.

Esta revisión no altera ni sustituye el run fallido `44161869072` ni el plan
vencido. El nuevo plan debe exponer el cambio de imagen y sus restantes
diferencias efectivas antes de una aprobación manual vinculada a su binario.

La preparación de código fija nombre, ID numérico y `READY` mediante
postcondiciones del proveedor. El workflow comprobará además la deprecación con
la API, verificará la custodia privada y comparará ambos JSON completos sin
publicarlos. El contrato admite esta configuración únicamente para planificación
comparativa: rechaza explícitamente cualquier apply de la candidata, incluso si
se entrega un documento con apariencia de aprobación. La referencia AA68 y su
TTL original se conservan intactos; ninguna aceptación se amplía con este cambio.
