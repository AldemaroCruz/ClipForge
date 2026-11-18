# INT: autorización del primer apply de fundación

La autorización del propietario activa exclusivamente las 42 creaciones del
plan del run `44194990499`, configuración
`bb4d10414b56c7c264ef8d4bc5649c08f2a9163b`. El commit nuevo contiene el contrato y
los controles; su SHA completo se suministra en el dispatch y queda ligado al
informe de controles y a la decisión canónica. No se incorpora una autorreferencia.

| Objeto privado original | Generación | SHA-256 |
| --- | --- | --- |
| manifest.json | 1794956399393543 | c30520602a48835b9c7ecc4f582020d5d8f7d648c8659a9a4804fc11da1553bf |
| int.tfplan | 1794956398925734 | 6ce16847341786469e52facebabd89f458933cc4c46f689a102f1d61ca556de7 |

Estos objetos, el JSON privado y el manifiesto no se reescriben ni se presentan
como generados por los controles nuevos. El contrato anterior, incluido
`planning_candidate`, se conserva como el blob original de `bb4d104` en
`config/int-foundation-history/bb4d104-contract.json`. Su estado histórico no es
una autorización. El registro vigente es `config/owner-risk-acceptance.json`;
su contenido canónico y hash también están ligados al contrato activo.

El límite del apply es **2026-11-18 16:59:58 America/Guatemala**
(`2026-11-18T22:59:58Z`), sin extender las 24 horas originales. La aceptación
temporal de riesgos vence como máximo el **2026-11-27 23:59:59** de Guatemala;
no prolonga el plan y pierde validez si cambian sus condiciones.

## Condición efectiva por etapa

`private_plan.apply_requires` en el resumen original es una descripción genérica
del procedimiento de runtime. Se conserva intacta como evidencia histórica.
La condición efectiva está en `.github/workflows/int-e2e-apply.yml`, que obtiene
la aprobación manual de `int` y ejecuta `check_int_foundation apply` sobre el SHA
del dispatch. El adaptador llama a `int_release.apply_saved` una sola vez.

Para `stage=foundation`, `require_foundation_ci` exige el informe nativo completo
del SHA nuevo, su integridad, las clasificaciones reproducibles y una decisión
específica con hash. `verify_owner_decision` y `verify_plan_bridge` vinculan ambos
commits, las referencias originales, HCL/startup/inputs/proveedores, el estado
inicial y los plazos. La imagen se consulta de nuevo por WIF y debe conservar el
ID aceptado, READY, arquitectura y ausencia de deprecación. Terraform inicializa
con lockfile readonly y aplica únicamente el binario verificado, con locking
nativo y comprobación de estado antes y después de init.

Para `stage=runtime`, se conservan el mismo commit de plan/controles, el gate real
del CI de aplicación y la comprobación del digest publicado. Las publicaciones,
Jobs y bootstrap conservan sus controles de aplicación. Sus fallos permanecen
visibles; esta autorización no convierte ninguno en success. Cloud Run y los
tres Jobs son una fase futura, fuera de estas 42 direcciones.

## Aceptaciones y comprobaciones pendientes

Se conserva el cifrado administrado por Google con las cinco detecciones LOW.
F-AUDIT-0077 cubre sólo las dos detecciones MEDIUM de media/backups y la alternativa
Cloud Audit Logs de 30 días, todavía pendiente de validación operativa real.
F-SAST-EXEC cubre sólo B404:16 y B603:169/180 del driver inalterado con SHA-256
`70982d2f5867d0101a181967d182058514e8c82a77423e5eceb09eb0cf89761b`;
no se modifica ese archivo, sus llamadas ni la construcción de comandos de apply.

F-VM-XML se acepta temporalmente para `debian-cloud/debian-13-trixie-v20261116`,
ID `5913446147369107523`, responsable AldemaroCruz: creación, arranque previsto e
inventario propios. No es remediación ni resultado de un scan. PostgreSQL debe
permanecer enmascarado, sin clúster/listener 5432, usuarios, lectura de secretos,
SQL, migraciones o activación. Inventario/SCA de esa VM y validación de auditoría
se obtienen después del apply; no se atribuyen scans de imágenes de CI a la VM.

El costo aceptado es USD 13.93/mes con los supuestos y exclusiones de
`config/tf-int01-costs.json`; no constituye un techo de gasto. Un fallo parcial
conserva el estado, registra un diagnóstico sanitizado y exige revisar los
recursos creados antes de otra ejecución. No hay retry, destroy ni renovación
automática del plan.
