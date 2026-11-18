# Recuperación INT: revisión pendiente de la ruta de apply

**Propuesta de controles y revisión F-SAST-EXEC; no registra aceptación ni
autoriza grants, apply o imports efectivos.** La ruta nueva está implementada como propuesta; todavía
necesita revisión de sus fuentes exactas, evidencia Actions del futuro commit
de controles y decisión del propietario. Un plan verde y WIF correcto no satisfacen esos requisitos.

## Plan concreto y antecedentes que no se trasladan

| Campo | Identidad que debe permanecer ligada a la revisión |
| --- | --- |
| Plan productor | run `44219757502`, configuración `264d1cfad6500e1abd60d3e7f966a3614a3a5831` |
| Manifiesto privado | generación `1794967145187552`; SHA256 `a6cd844f31900ab7d1c6012fa3a7b936a86698218551b2582a63266d88f4189e` |
| Binario privado | generación `1794967144807369`; SHA256 `c75860660cee6f3ac1c929963bac70f660e08d40767610e1895cd115f2462469` |
| Vencimiento propio | **2026-11-19T01:59:04.701513Z**, equivalente a **18nov 19:59:04.701513 UTC−6** |
| Backend | `clipforgebeta2-tfstate-int` / `terraform/int/tf-int-01` / workspace `default` |
| Estado parcial de entrada | generación `1794961942265923`, serial `5`, lineage `813c84a2-2ef1-ceb3-177e-3a2c3b815066`, SHA256 `7b4018183c1df6652200efb620cc4d71d5b8c3d39b08e80588fdd98cf9262648` |
| Acciones revisadas | 17 creaciones, 20 direcciones ya gestionadas sin cambio y cinco imports sin cambio; 42 direcciones finales |

Estas referencias proceden de la revisión coordinada; aquí no se abrió estado,
plan completo o credenciales ni se repitieron consultas de GCP. El helper debe
obtener también nombre/tamaño/JSON/inputs/versiones del manifiesto exacto y
contrastarlos, no completarlos desde este documento.

El binario `6ce168…de7` del run `44194990499` quedó retirado tras el apply parcial
`44208225603`. Su aceptación no cubre `c758606…2469`, los cinco imports, un nuevo
llamador ni privilegios adicionales. Tampoco se amplía el TTL anterior.

## Matriz F-SAST-EXEC

Fuente de los tres sitios nativos, comprobada sin modificarla:
`scripts/tf_int_plan.py`, SHA256
`70982d2f5867d0101a181967d182058514e8c82a77423e5eceb09eb0cf89761b`.

| Sitio nativo | Huella preservada | Riesgo y condición que debe revisar la nueva decisión |
| --- | --- | --- |
| B404, línea16 | columnas0–17, LOW, rango16 | Importa `subprocess`; no implica que todos sus llamadores sean seguros. |
| B603, línea169 | columnas13–122, LOW, rango169 | Ejecuta argv con cwd privado, captura de salida y timeout1200s. No usa shell; hereda entorno y autoridad del proceso. Deben revisarse cada llamador y sus argumentos reales. |
| B603, línea180 | columnas13–81, LOW, rango180–181 | Resuelve Terraform en PATH y ejecuta `version -json`, timeout30s. Verifica1.15.8; esa comparación no autentica por sí sola el contenido del ejecutable de PATH. |

Las coordenadas identifican advertencias preservadas, no un scan nuevo de la
ruta por implementar. Mantener SHA709 **no transfiere F-SAST-EXEC** cuando
cambian llamador, argv, ejecutable, plugins, workflow o privilegios. La nueva
decisión debe nombrar esos tres sitios y el nuevo contexto completo, conservando
los findings y sin excepción por regla/directorio/herramienta.

| Capa de ejecución | Estado de la revisión |
| --- | --- |
| Driver nativo SHA709 | Mismos tres sitios; archivo intacto. |
| `int_release.py`, SHA `9c5cf839a4cc6ab6479c321b3bd0804ddbc26507a53629326fd7ba2976d31878` | Ruta histórica de apply42, no aprobación de la recuperación. |
| `int_foundation_recovery.py`, ruta de plan | Caller nuevo de init/validate/plan/show; su propuesta no aceptaba un apply. |
| Nuevo caller de saved-plan apply | `scripts/int_foundation_recovery_apply.py:apply_reviewed`, hash en el índice del ZIP. Implementado, pendiente de aceptación de sus fuentes exactas y argumentos. El mismo sink169 ejecutaría un binario con17create+5imports efectivos. |
| Workflow de apply revisado | `.github/workflows/int-foundation-recovery-apply.yml`, hash en el índice del ZIP; pendiente de decisión. Fija ruta, acciones y closure completa. Debe ser manual, rama autorizada, GitHub-hosted, Environment `int`, WIF existente y aprobación nueva. |
| Proveedor y ejecutables | Terraform1.15.8 sin wrapper, Google8.11.0/lock readonly y acciones fijadas; conservar comprobaciones reales. PATH/Docker daemon/plugins y credenciales temporales siguen siendo fronteras de confianza. |

El argv propuesto para el nuevo caller es `init -input=false
-lockfile=readonly -reconfigure -no-color -backend-config=backend-int.hcl`,
seguido exclusivamente de `apply -input=false -no-color -lock=true
-lock-timeout=120s <binario_guardado_verificado>`. Si se añade `show` u otra
invocación, debe figurar también en la revisión final. No replan implícito,
`-target`, import CLI, state push, migración, `-lock=false` o force-unlock.

El launcher del runner no queda aislado por los flags de los contenedores de
checks: puede acceder al daemon Docker y a credenciales WIF temporales. La nueva
closure debe mantener logs privados, snapshot completo para secretos, controles
Bandit nativos y fuente/hash de cada dependencia de ejecución. Ningún resultado
de estos controles acepta otros SAST/HIGH/CRITICAL ni cambia CI de aplicación.

## Autoridad adicional: seis roles temporales

El [delta IAM versionado](../config/int-foundation-iam-delta.json) leído marca
`proposal_only_owner_authorization_required` y `grants_executed=false`; eso es
el estado de la propuesta, no una consulta de IAM efectivo. Principal propuesto:
`clipforge-terraform-int@clipforgebeta2.iam.gserviceaccount.com`. El administrador
ejecutaría sólo un paquete autorizado aparte; Terraform/deploy no se conceden
estos permisos a sí mismos.

| Rol temporal propuesto | Permisos y alcance directo | Capacidad residual a decidir expresamente |
| --- | --- | --- |
| Project policy | Proyecto: `resourcemanager.projects.setIamPolicy`, `iam.roles.get/create`. GET de política ya cubierto. | Puede modificar la política del proyecto y conceder autoridad a sí mismo u otros; Create no restringe el nombre/contenido de todos los roles nuevos. |
| Logging config | Proyecto: buckets create/get; operations get; sinks create/get; views create/get/getIamPolicy/setIamPolicy. | Creación se autoriza en padres; SetIamPolicy de vistas puede delegar lectura, aunque este rol no lea payloads directamente. |
| Secret create | Proyecto: `secretmanager.secrets.create`. | El permiso de creación en el padre no queda limitado técnicamente a dos nombres aún ausentes por una condición sobre esos futuros secretos. |
| Two new secret policies | Get/GetIamPolicy/SetIamPolicy, limitados por servicio/tipo/nombres exactos a `postgres-ca` y `bootstrap-admin`. | Puede delegar acceso a sus versiones/payloads mediante política. No da Set adicional sobre los dos passwords existentes; sus cinco imports deben seguir NO-OP. |
| Fixed IAP VM policy | Get/SetIamPolicy sobre instancia ID `1670495097211408131`, con TTL. | Puede delegar túneles a esa VM; no equivale a aislamiento de todos los accesos indirectos del principal. Una recreación cambia el ID. |
| PostgreSQL SA policy | Get/SetIamPolicy sobre la SA PostgreSQL exacta, con TTL. | Puede delegar impersonación/actAs sobre esa SA, aunque no se conceda token creation directamente. |

**Project SetIamPolicy es el riesgo dominante.** Su API cambia la política de
acceso del proyecto; preservar etag/terceros en la receta limita la operación
prevista, no convierte ese permiso en una capacidad limitada a un miembro o
rol. [API oficial](https://docs.cloud.google.com/resource-manager/reference/rest/v1/projects/setIamPolicy).

El límite propuesto de cada binding es máximo7200s y nunca después de
2026-11-28T05:59:59Z. **El TTL no contiene a un principal capaz de modificar su
propia política**: durante la ventana podría crear otro grant sin esa condición.
Es una conclusión de la combinación de permisos, no una acción ejecutada. Las
condiciones sólo restringen los bindings a los que pertenecen y no anulan grants
incondicionales existentes. [IAM Conditions](https://docs.cloud.google.com/iam/docs/conditions-overview).

La propuesta no incluye grants directos de payload, claves SA, roles.update,
delete/undelete ni cambios de aplicación. La capacidad de delegarlos por política
sigue siendo un riesgo residual; su ausencia en la lista directa no demuestra
imposibilidad. Las definiciones de roles pueden permanecer tras caducar sus
bindings: no declarar retirada/borrado automáticos ni ejecutarlos sin alcance.

F-VM-XML, F-AUDIT-0077 y cifrado Google-managed conservan condiciones y vigencia;
no se declaran remediados u operativos. Las futuras concesiones adicionales y
esta nueva ejecución necesitan su decisión específica; no se aceptan aquí.

## Puentes que la implementación debe conservar cerrados

La inspección de `int_release_state.py` corresponde a SHA256
`c7213b053002fe559e08874eee95ce693906d56a6a9825d6680d63d708d49daa`.
Son contratos históricos, no evidencia de ejecución del recibo nuevo.

- `check_int_foundation` retira el contrato anterior mediante
  `recovery_preparation_only`. No quitar ese guard para hacer pasar el plan nuevo.
- `int_release.apply_saved` presupone esquema original, backend inicial y
  exactamente42create. No cambiar/falsear esos datos ni sus verificadores para
  introducir un plan desde serial5 con cinco imports.
- `int_release_state.verify_parent` exige esquema de parent anterior y snapshot
  inicial serial1; `emit_foundation_receipt` usa `parent['commit']`. El manifiesto
  recovery tiene otras claves y ancestry. No emitir un recibo antiguo rotulado
  como si procediera de ese contrato.

Se propone un recibo recovery propio: manifiesto/binario exactos del plan,
configuración264d, control nuevo, decisión/evidencia/paquete IAM por SHA,
antecesor parcial serial5 y estado final leído privadamente por generación.
Debe validar lineage igual, serial posterior y las42 direcciones exactas,
sin deposed/tainted/recursos inesperados ni publicar atributos/outputs. Su emisor
debe nombrar el workflow/run/control que realmente aplicó, sin reutilizar
artificialmente el emisor histórico. Reconocer ese recibo en runtime exige una
revisión explícita posterior; su gate actual continúa cerrado.

## Secuencia propuesta antes de pedir aprobación

1. Finalizar caller/workflow y su snapshot exacto; ejecutar únicamente controles
   afectados y registrar la nueva evidencia completa. Ningún SHA de fuente aún
   por escribir se da por revisado en este documento.
2. Separar tres identidades: configuración productora264d, controles de apply
   nuevos **C**, y manifiesto/binario inmutables. C se entrega como input de
   dispatch y en la decisión externa después del commit; debe coincidir con
   `GITHUB_SHA` y evidencia fresca de C. No embebido autorreferencial de C dentro
   del archivo que determina C, ni reutilización del reporte de otro control.
3. Obtener aprobación del paquete IAM exacto y de su riesgo de delegación,
   con su expiración concreta. La receta administrativa y su hash se revisan
   separadamente; no se ejecuta como reparación automática de un403.
4. Preparar decisión externa del propietario que vincule refs completas
   nombre/generación/SHA/tamaño de manifiesto/binario/JSON, ambos commits,
   backend parcial, once fuentes del módulo/imports, versión/lock, imagen,
   acciones17create+5imports, evidencia nueva y aceptaciones individuales.
   El plazo efectivo es el menor entre TTL del plan, decisión, riesgos y grants;
   nunca renueva ni reconstituye el plan desde su JSON.
5. Sólo tras otra aprobación manual de `int`, verificar WIF/identidad/imagen,
   políticas de los cinco imports y estado parcial actual (sin lock, mismos
   bytes/generación/serial). Repetir el guard tras init; después aplicar una vez
   ese mismo archivo. El acceso técnico y la aprobación de int no sustituyen la
   aceptación específica de la nueva ruta/privilegios.
6. Si falla, preservar estado y diagnóstico sanitizado, sin destroy, retry ni
   segundo plan automático. Distinguir fallo nativo parcial de apply terminado
   con fallo posterior del recibo. Tras éxito, emitir el recibo nuevo y comprobar
   VM/auditoría dentro de su autorización; no concluir backups/restore, SQL,
   aplicación, Jobs o seguridad de VM por el éxito de Terraform.

Si el plan vence antes de esas decisiones, detener la ruta. Un plan posterior
requiere su propia revisión; este documento no aprueba su sustitución.

## Implementación de revisión entregada

`config/int-foundation-recovery-apply.json` es una propuesta **inactiva**. El
contrato histórico sigue en `recovery_preparation_only`: el aplicador legacy de
42create continúa rechazado. No se reescribe el manifiesto del productor.
El workflow nuevo hace dos checkouts: controles del dispatch y configuración
264d en `plan-source`. El helper contrasta once fuentes/imports, versiones y
lock, fingerprint original del productor y evidencia nueva del control C.
Sólo existe `init -lockfile=readonly` seguido de `apply <archivo>` con locking
nativo; no hay replan, import CLI ni ruta runtime en este workflow.

La decisión externa sigue `pending` por defecto. La aprobación futura debe
nombrar este binario, el commit C completo, la evidencia fresca de C, los tres
sitios nativos conservados de F-SAST-EXEC y el nuevo contexto de ejecución.
La huella709 del driver no cambió; no constituye aceptación de este caller.
El inventario del ZIP contiene los hashes concretos de las fuentes propuestas.
Un resultado local o sintético no se presenta como ejecución Actions de C.

El paquete IAM queda ligado por SHA del manifiesto y vencimiento exactos en la
propuesta. El helper valida bytes del índice/recibos sanitizados y las seis
concesiones completadas. Además vuelve a leer sus políticas y definiciones
actuales antes y después de init: un recibo histórico no acredita que una
concesión sobreviva a una retirada posterior. La presencia de bindings no
resuelve Deny/PAB/org policies ni demuestra permiso efectivo de cada create;
una denegación real sigue siendo fallo, sin ampliar privilegios ni reintentar.
El helper no crea roles ni concede bindings. Esas operaciones pertenecen a la
receta administrativa, sólo después de aprobar su paquete exacto.

El recibo de éxito usa un schema propio de recuperación con antecedente
serial5. Rechaza taint/deposed/recursos inesperados, exige serial posterior y
una nueva generación actual, y conserva configuración264d y controlesC sin
reasignar sus identidades. Runtime no acepta automáticamente ese schema.
La intención de apply se registra antes del comando; un timeout sin log activa
inspección privada del estado. Si Terraform termina pero falla el recibo, se
informa ese caso y se bloquea cualquier reintento automático.

La propuesta de host key es una intervención independiente. No está en el plan
44219757502 ni la autoriza esta preparación. La lectura preparatoria y sus
hashes están en el ZIP; sólo una autorización posterior permitirá metadata,
stop/start o restauración. PostgreSQL, inventario real del guest y auditoría
operativa continúan pendientes de sus comprobaciones respectivas.
