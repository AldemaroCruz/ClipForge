# Workflow principal del Hito A de INT

El único `workflow_dispatch` que entrega o modifica el Hito A es
[`.github/workflows/int-hito-a.yml`](../.github/workflows/int-hito-a.yml). La
aprobación del environment `int` queda ligada al SHA exacto escrito en
`approved_commit`; el workflow rechaza una rama, reejecución o checkout que no
coincida.

## Tres jobs y una sola imagen

| Job | Credenciales | Resultado |
| --- | --- | --- |
| `frontend` | Ninguna; sólo `contents: read` | Sintaxis JavaScript, allowlist HTML/estáticos y regresiones de interfaz. |
| `api` | Ninguna; sólo `contents: read` | Snapshot Git exacto y Gitleaks, suite backend completa con PostgreSQL efímero real, Bandit evaluado con excepción INT, una OCI `linux/amd64`, smoke tests, inventario independiente, SBOM y Trivy sin excepciones. |
| `deploy` | Único job con environment `int`, `id-token: write` y WIF | Publicación por digest, PostgreSQL/TLS, versiones de secretos, Terraform, migración, administrador, aceptación API/browser y reemplazo controlado. |

`frontend` y `api` se ejecutan en paralelo sobre `ubuntu-24.04`. `deploy`
declara `needs: [frontend, api]` y descarga por ID sólo la OCI que produjo
`api`. El hash del archivo, su tamaño, el digest del manifest, el resultado del
job y el recibo de scanners se vuelven a validar antes de pedir WIF. La imagen
de aplicación se construye una sola vez; la imagen auxiliar de CI no es un
artefacto desplegable.

La OCI contiene el frontend estático y `app.int_demo:app`. Es la única imagen
que usa el servicio `clipforge-int-api` y los jobs fijos
`clipforge-int-migrate` y `clipforge-int-bootstrap`; no incluye worker ni
componentes multimedia.

## Orden protegido

Dentro del único job `deploy`, el entrypoint
`python -m scripts.int_hito_a_delivery` mantiene un estado privado y obliga al
siguiente orden:

1. `verify-artifact`, todavía sin credenciales cloud.
2. WIF como `GCP_TERRAFORM_SA`; `preflight` acredita antes de cualquier
   mutación tanto la concesión al propietario sobre el secreto administrativo
   como la lectura/escritura de la política IAP del servicio exacto.
3. WIF como `GCP_DEPLOY_SA`; `publish` y `configure` publican el digest exacto,
   fijan SSH a la clave Ed25519 publicada del Noble, inicializan sólo un disco
   en blanco y crean las versiones de secretos. Si PostgreSQL ya existe, los
   dos passwords se contrastan en memoria con sus verificadores SCRAM antes de
   publicar versiones nuevas; el helper no modifica roles ni expone hashes.
4. WIF como `GCP_TERRAFORM_SA`; `infra` aplica exactamente el plan guardado para
   un servicio y dos jobs.
5. WIF nuevamente como `GCP_DEPLOY_SA`; `migrate` ejecuta los jobs sin retry y
   `accept` en fase `prepare` crea la línea base de persistencia.
6. WIF como `GCP_TERRAFORM_SA`; `replace` comprueba primero
   `run.services.update`, cambia sólo el nonce de la plantilla y crea una
   revisión nueva con el mismo digest.
7. Una credencial Terraform hace sólo las lecturas de control y un OAuth access
   token de `GCP_DEPLOY_SA` atraviesa IAP. `accept` en fase `verify` prueba API y
   persistencia; Playwright 1.64.1 usa Chrome/Chromium preinstalado para probar
   la interfaz real, CSS/JS, login admin/usuario, usuarios, auditoría y logout.

`configure` recibe los secretos únicamente mediante el environment del step y
conserva sólo números de versión y recibos sanitizados. La identidad federada
del workflow nunca es `GCP_MIGRATOR_SA`; los jobs de Cloud Run ejecutan con su
identidad de runtime definida por Terraform.

El access token de Deploy lleva `openid` y `userinfo.email` y se limita a la
cuenta con `roles/iap.httpsResourceAccessor`. No se representa como ID token ni
se comparte con `frontend` o `api`.

## Riesgo del runner administrado en INT

[`config/int-runner-risk-acceptance.json`](../config/int-runner-risk-acceptance.json)
registra la decisión del propietario del 24 de noviembre de 2026. Para
`ubuntu-24.04` administrado por GitHub, los findings del OS, kernel, paquetes
preinstalados y toolchain de credenciales son informativos en INT, incluso si
son HIGH/CRITICAL. No se exige igualdad de imagen, boot, kernel o huellas entre
jobs.

La excepción del runner no alcanza la OCI de aplicación, Gitleaks, PostgreSQL
de prueba, integridad de artefactos, IAM/OIDC, IAP ni TLS. Bandit tiene una
decisión temporal distinta y más estrecha, descrita a continuación. La
continuidad dentro de un mismo job se conserva. Los recibos históricos
`host_rejected` siguen siendo evidencia histórica y no se reescriben como
limpios.

## Bandit evaluado con excepción INT

[`config/int-hito-a-bandit-acceptance.json`](../config/int-hito-a-bandit-acceptance.json)
registra una excepción temporal exclusiva de `int-hito-a`; no se reutiliza en
PROD ni en el validador global. La decisión conserva como deuda pendiente los
142 findings nativos de Bandit 1.9.4 del commit
`cbc05133cd96bf3bd79991d8f2157775624c755f`: 124 LOW y 18 MEDIUM. También
registra por separado las 12 incorporaciones LOW revisadas del Hito A: tres
B404, siete B603 y dos B105. Los B404/B603 corresponden a ejecuciones sin shell,
con ejecutables y argumentos acotados; los B105 son nombres de variables de
entorno y no valores de autenticación.

El informe nativo completo conserva cada finding y su severidad original; no
se declara «Bandit limpio» ni se presenta la deuda como corregida. La política
compara un multiset exacto por ruta, regla, severidad, confianza, CWE y hashes
de fuente/contexto. No usa solamente el total 142/154 y conserva multiplicidad
para los dos B105 que comparten fragmento. El recibo público debe indicar
`Bandit evaluado con excepción INT`.

Siguen bloqueando errores del scanner, un informe incompleto o inconsistente,
una versión distinta, un fragmento aceptado que cambió, findings no revisados,
cualquier HIGH y cualquier MEDIUM nuevo. La vigencia es del
24 de noviembre de 2026 al 24 de diciembre de 2026 a las 23:59:59 UTC; fuera de
esa ventana el gate vuelve a fallar. El workflow global y PROD mantienen su
política anterior de cero findings.

## Configuración requerida

Variables de repositorio/environment: `GCP_PROJECT_ID`,
`GCP_PROJECT_NUMBER`, `GCP_REGION`, `GCP_WIF_PROVIDER`, `GCP_DEPLOY_SA`,
`GCP_TERRAFORM_SA`, `ARTIFACT_REGISTRY_REPOSITORY`, `CLOUD_RUN_SERVICE`,
`TF_STATE_BUCKET` y `TF_STATE_PREFIX`. El controlador exige el proyecto,
región, repositorio y servicio exactos de INT; `CLOUD_RUN_SERVICE` debe ser
`clipforge-int-api`.

Secretos del environment `int`: `INT_APP_PASSWORD`,
`INT_MIGRATOR_PASSWORD`, `INT_POSTGRES_CA`, `INT_PG_SERVER_CERT`,
`INT_PG_SERVER_KEY` e `INT_BOOTSTRAP_ADMIN_JSON`. No se aceptan como inputs ni
argumentos de la CLI.

Después de una entrega exitosa, `admin@ixbalam.studio` entra a la URL protegida
por IAP y obtiene la credencial inicial sin pasarla por logs ni artefactos:

```text
gcloud secrets versions access latest --project=clipforgebeta2 --secret=clipforge-int-bootstrap-admin
```

El binding se limita a ese secreto y se crea en el mismo plan revisado. Si el
preflight devuelve
`terraform_cannot_grant_bootstrap_credential_access`, no se publica la imagen,
no se toca PostgreSQL y se requiere restaurar temporalmente al Terraform SA los
permisos `secretmanager.secrets.getIamPolicy` y
`secretmanager.secrets.setIamPolicy` sobre ese secreto exacto. Si devuelve
`terraform_cannot_manage_iap_policy`, se requieren
`iap.webServices.getIamPolicy` e `iap.webServices.setIamPolicy` sobre
el proyecto `816643438938`, antes de crear el servicio prospectivo. El plan
revisado sigue limitando los bindings al IAP de `clipforge-int-api`.
`terraform_delivery_iam_permissions_missing` indica que faltan ambos grupos y
permite corregirlos en una sola intervención. Los tres códigos detienen la
entrega antes de publicar o configurar recursos.

## Evidencia, estado privado y reversión

El artefacto final permite únicamente `delivery-receipt.json`, recibos de fallo
con códigos fijos y los reportes sanitizados de aceptación API/browser.
`delivery-state.json`, el estado privado de la
cuenta sintética, credenciales, tokens, certificados, claves y payloads de
Secret Manager nunca se suben.

La aceptación crea una cuenta sintética, registra la revisión inicial, fuerza
un reemplazo real de la revisión de aplicación y vuelve a probar login,
autorización, listado administrativo, auditoría, logout y persistencia tanto por
HTTP como en un browser real. Si la fase `verify` falla, el step `rollback` se
ejecuta con la identidad Terraform,
restaura y verifica 100 % del tráfico en la revisión registrada por `prepare`,
emite el recibo de reversión y conserva fallido el run original. PostgreSQL y
sus datos no se revierten ni se eliminan.

Si el fallo ocurre antes de comenzar el apply de reemplazo, rollback registra
`not_required` y no emite una escritura redundante contra Cloud Run.

## Workflows históricos

Los mutadores históricos se conservan como fuente auditable pero ya no tienen
`workflow_dispatch`. Son `workflow_call` inertes porque todos sus jobs tienen
un guard constante falso:

- `int-db01-noble-apply.yml`, `int-db01-noble-bootstrap.yml`,
  `int-db01-noble-intervention.yml` e `int-db01-noble-jobs.yml`;
- `int-demo-a-apply.yml`, `int-demo-a-publish.yml` e
  `int-demo-a-secrets.yml`;
- `int-e2e-apply.yml`, `int-e2e-bootstrap-db.yml`, `int-e2e-jobs.yml`,
  `int-e2e-runtime.yml` e `int-e2e-secrets.yml`;
- `int-foundation-close.yml` e `int-foundation-recovery-apply.yml`.

Los workflows de observación y plan que no aplican cambios conservan su entrada
manual. Esta definición es validación estática del contrato; sólo un run de
GitHub Actions observado sobre el SHA publicado acredita la entrega real.
