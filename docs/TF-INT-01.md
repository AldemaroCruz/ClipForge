# TF-INT-01: primer plan de la base de INT

Autorizado: implementar y planificar desde Actions. No autoriza apply,
despliegue, import, migración de estado, cambios IAM, secretos ni aceptación de
hallazgos. DEV, candidatas, servicio operativo y SEC-05 se conservan.
GCP-AUTH-01 cerró autenticación y lectura de proyecto, no permisos de despliegue.

## Fuentes y separación

La raíz es `infra/gcp/int-base`; el workflow manual es `tf-int-plan.yml`.
Los borradores locales `infra/gcp/int`, `infra/gcp/bootstrap`, `int-infra.yml`
y sus helpers se conservan fuera de esta selección: incluyen otro alcance,
IAM, Cloud Run y una opción apply. No se ejecutan ni se publican aquí.

Terraform 1.15.8 y Google 8.11.0 están fijados exactamente. El lock se obtiene
con firmas de HashiCorp y hashes para Linux/amd64 y Windows/amd64. El ejecutor
comprueba la versión real y usa `-lockfile=readonly`; no hay módulos remotos,
provisioners ni data sources externos ejecutables. Checkout precede a auth.

Referencias, todas propiedad del bootstrap, sin resource/import ni versiones
de secretos: bucket `clipforgebeta2-tfstate-int`, Artifact Registry
`us-central1/clipforge-int`, proveedor WIF `clipforge-gh-int/github`, cuentas
`clipforge-{terraform,deploy,api,worker,migrate,postgres}-int` y contenedores
`clipforge-int-pg-{app,migrator}-password`. Las cuentas son las seis del
bootstrap, no cuentas nuevas. Las APIs y sus políticas siguen bajo bootstrap.

Proyecto fijo `clipforgebeta2`, número comprobado `816643438938`, región
`us-central1`, zona `us-central1-a`. Se contrastan las variables no secretas de
`int` con el bootstrap. Solo se usa su cuenta Terraform mediante WIF.

## Estado y límites de la ejecución

El prefijo independiente es `terraform/int/tf-int-01`, bajo el prefijo base
`terraform/int` del bootstrap. Antes de init se consulta solo metadata del
bucket: proyecto, acceso uniforme, prevención pública y versionado. Se lista
la base autorizada `terraform/int/` separando vivos, versiones y soft delete,
con paginación completa y metadata de nombre, generación, fechas y tamaño.
El backend efectivo se conserva en `terraform/int/tf-int-01`, workspace `default`;
no se cambia al prefijo padre ni se crea uno por ejecución.

La reejecución reconoce exclusivamente la foto inicial inspeccionada en privado:
`default.tfstate`, generación `1794599421671184`, 181 bytes, serial 1, Terraform
1.15.8, cero recursos y cero outputs. El helper fija su lineage y SHA-256 y
verifica los bytes por generación; no incorpora JSON de estado en el repo.
La ruta se contrastó con el bucket/proyecto y configuración versionada. Las
versiones históricas del lock incluyen init y plan, con la ruta exacta y fechas
coherentes con la inicialización. No se atribuye escritor concreto: la consulta
de auditoría no devolvió eventos. La aceptación depende de la identidad exacta
inspeccionada, no de atribuirla al primer intento ni de una fecha aproximada.

Un `.tflock` vivo siempre bloquea, sin presumir que es huérfano por su edad.
Sus generaciones históricas no son bloqueos activos. Estado distinto, otra
lineage, historia de estado adicional, otro workspace u objeto desconocido bajo
el backend efectivo bloquean antes del plan. Sin estado actual pero con historia
de estado también se detiene: no se crea un reemplazo. Sin estado ni historia
se distingue backend no inicializado; cualquier snapshot nuevo no reconocido
requiere revisión antes de planificar. No hay desbloqueo forzado ni borrado de
objetos. Las fotos privadas se eliminan y solo metadata permitida llega al resumen.

El backend GCS conserva locking nativo. El único plan real usa
`-lock=true -lock-timeout=120s -detailed-exitcode`, sin target ni refresh falso.
0 es sin cambios; 2 es con cambios; 1 es error. Los 403 conservan una evidencia
saneada con operación, permisos y recursos; no activan concesiones de roles.
Las operaciones normales de bloqueo y backend sobre este prefijo están
autorizadas; no equivalen a aplicar infraestructura.

El plan binario, JSON completo, logs privados y configuración de backend viven
solo en scratch privado del runner. La limpieza final elimina ese scratch y
el post de auth elimina `gha-creds-*.json`. No queda un plan completo disponible
para un apply futuro. Solo `summary.json` y `summary.md`, construidos mediante
campos permitidos, se publican como artefacto durante siete días. No contienen
tfstate, tfplan, credenciales, valores de secretos ni dumps de configuración.

## Propuesta base y red

El diseño contiene 16 instancias de recursos administrados: una frontera local
de validación, VPC, dos subredes, ruta, router, NAT, IP interna reservada,
cuatro firewalls, disco de datos, VM y dos buckets. Este inventario es del
diseño; solo un plan real exitoso permite afirmar sus acciones efectivas.

- VPC propia sin subredes automáticas. Run: `10.80.0.0/26`, tamaño válido para
  [Direct VPC egress](https://docs.cloud.google.com/run/docs/configuring/vpc-direct-vpc).
  PostgreSQL: `10.80.1.0/28`; ambas usan Private Google Access e IPv4.
- PostgreSQL no tiene IPv4 pública ni IPv6 pública. Entrada 5432 únicamente
  desde la subred Run y SSH 22 únicamente desde IAP `35.235.240.0/20`.
  Los firewalls apuntan solo a la cuenta PostgreSQL, con logging.
- NAT cubre exclusivamente la subred PostgreSQL. Firewall permite HTTPS 443
  hacia fuera y deniega el resto del egress de esa VM. Es un límite por puerto,
  no una lista de dominios. El tráfico de metadata/DNS de GCE requiere sus
  mecanismos de plataforma; no se promete aislamiento sin salida.
- NAT usa una IPv4 externa de traducción, sin IP pública asignada a la VM ni
  servicio accesible desde Internet. Se cobra incluso con la aplicación detenida.
- OS Login habilitado, claves SSH de proyecto bloqueadas, endpoints legacy y
  consola serial deshabilitados; Shielded VM con Secure Boot, vTPM e integridad.
  Los permisos IAP/OS Login/actAs del administrador requieren revisión separada:
  no se conceden aquí ni se declara administración ya comprobada.
- Boot de 10 GiB y datos de 20 GiB, `pd-standard`, separados. Boot no auto-delete;
  datos, VM y buckets tienen prevent_destroy. VM tiene deletion_protection.
  El contrato rechaza deletes/replaces, disco menor o perdido y buckets públicos.

## PostgreSQL y almacenamiento persistente

La imagen se resuelve mediante `debian-cloud/debian-13` y su self_link concreto
queda fijado en el plan privado de esa ejecución. Antes de un apply posterior
se debe revisar y fijar la imagen concreta en un nuevo plan. No usa Pro/ESM.
La receta nueva es independiente de imágenes, locks y datos de las instalaciones
locales; no las actualiza ni declara equivalencia de sus escaneos.

La receta prepara PostgreSQL 17, versión Debian `17.12-0+deb13u1`, identificada
en el [repositorio oficial Debian](https://packages.debian.org/trixie/postgresql-17).
APT solo consulta las suites trixie, updates y security por HTTPS; exige firmas
InRelease y hashes de paquetes con el keyring de la imagen. No usa curl-pipe,
repositorios sin firma, claves descargadas sin verificar o paquetes permisivos.
No descarga ni ejecuta esos paquetes durante el plan. La disponibilidad y
vigencia del minor se revisarán de nuevo antes de instalar.

El startup instala paquetes, conserva provenance local y deja el servicio
enmascarado y sin cluster. No formatea ni monta un filesystem nuevo, no
inicializa SQL, no cambia roles ni recupera contraseñas. Se niega a reconfigurar
un cluster existente. PostgreSQL 17 aún requiere probar compatibilidad con las
migraciones sintéticas de ClipForge; no se presume por los tests locales sobre 18.

El procedimiento protegido posterior debe: identificar el disco y revisar si
contiene datos antes de cualquier formato; montar por UUID; inicializar el
cluster en datos con checksums; configurar SCRAM-SHA-256 y cuentas app/migrator
separadas sin privilegios administrativos; instalar TLS con clave local 0600 y
certificado cuyo SAN cubra el hostname interno. `pg_hba` deberá rechazar hostnossl,
usar hostssl limitado a la subred Run y exigir verify-full en clientes. Sin
trust, TLS autofirmado sin verificación ni secretos en metadata/estado.

Para 1 GiB inicial: evaluar max_connections 20, pool pequeño, shared_buffers
128 MiB, work_mem 1 MiB, maintenance_work_mem 32 MiB; medir RAM, WAL, latencia e
IOPS antes de aceptarlo. [e2-micro ofrece 1 GiB y CPU fraccionaria compartida](https://docs.cloud.google.com/compute/docs/general-purpose-machines).
e2-small duplica RAM y CPU sostenida aproximada; el parámetro solo evalúa el
perfil, no garantiza capacidad ni aplica cambios.

Buckets `clipforgebeta2-int-media` y `clipforgebeta2-int-backups`: privados,
UBLA, PAP enforced, versionado y soft delete 7 días. Media conserva objetos
actuales sin expiración y retención mínima 7 días. Backups retiene mínimo 30
días, expira objetos actuales a 90 días. Versiones anteriores expiran después
de 30 días y al menos tres versiones nuevas. Retención no bloqueada, sin
force_destroy. Cifrado administrado por Google; no se crean KMS ni claves.
No hay grants IAM de buckets en esta raíz.

Backups posteriores: rol de creación de objetos para la VM revisado por separado,
pg_dump diario cifrado por TLS al bucket y prueba mensual de restauración en
disco/VM aislados. Objetivo propuesto RPO 24h y RTO 4h, todavía sin medición ni
garantía. PITR/WAL continuo y snapshots consistentes requieren otro diseño;
versionado/soft delete no prueban la recuperación de PostgreSQL.

## Costos y hallazgos sin aceptar

Estimación pública, USD, 730 h/mes: micro 6.11; 30 GiB pd-standard 1.20;
NAT para una VM 1.02; IPv4 de NAT 3.65; un GiB procesado por NAT 0.045;
20 GiB GCS entre media y backups 0.40. Total aproximado **12.43/mes**;
con e2-small **18.55/mes**, sin aplicar. Son escenarios, no cotizaciones.
El free tier puede reducir VM/discos si la cuenta cumple sus límites compartidos;
no se da por disponible. Incluso con esos créditos queda NAT/IPv4 y uso GCS.
Se excluyen impuestos, egress a Internet, operaciones, logging fuera de franquicia,
Secret Manager, Artifact Registry y la siguiente etapa Cloud Run/Jobs.

Fuentes y supuestos versionados en `config/tf-int01-costs.json`:
[VM](https://cloud.google.com/products/compute/pricing/general-purpose),
[discos](https://cloud.google.com/compute/disks-image-pricing),
[NAT](https://cloud.google.com/nat/pricing),
[GCS](https://cloud.google.com/storage/pricing).

La revisión Trivy IaC usa todas las severidades, sin ignores ni supresiones.
HIGH/CRITICAL bloquean el plan al igual que el nivel de bloqueo de los scanners
de aplicación; los demás quedan visibles, registrados y no aceptados.
Revisión inicial: 52 checks correctos, cinco LOW de CSEK/CMEK
(GCP-0033, GCP-0034, GCP-0066) y dos MEDIUM de access logging de buckets
(GCP-0077). CSEK introduciría material secreto y CMEK/logging necesitan diseño
de costos/IAM propio: no se añaden automáticamente ni se ocultan esos findings.
Apply, release y despliegue permanecen sin autorización, además del bloqueo
independiente del CI de aplicación. No se reabre una auditoría general de CVE.

## Orden futuro, sujeto a nueva autorización

1. Revisar el primer plan y sus permisos faltantes, costos y hallazgos; confirmar
   imagen concreta, disponibilidad de nombres y compatibilidad PostgreSQL.
2. Resolver explícitamente acceso IAP/OS Login, IAM mínimo de media/backups y
   política de claves/logging. No se ejecuta esta tarea al planificar.
3. Generar y revisar otro plan completo: el de TF-INT-01 se elimina. Autorizar
   su apply con procedimiento propio; no existe opción apply en este workflow.
4. Terraform ordenaría red, subredes, ruta/NAT/firewalls, disco/IP y VM; buckets
   pueden ir en paralelo. Inicializar disco/SQL, TLS y roles sería otro paso
   protegido, luego carga/rotación de secretos y restauración sintética probada.
5. Corregir bloqueos de imagen/aplicación y adaptar persistencia, tareas de fondo,
   migraciones y conexiones TLS. Solo entonces diseñar Cloud Run/Jobs, IAM de
   runtime/worker/migrator, Direct VPC, almacenamiento y digest real aprobado.
   No hay Cloud Run, Jobs, balanceador, Cloud SQL, GKE, Redis ni digest ficticio
   en el plan base.
