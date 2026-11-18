# Verificación posterior de FUNDACIÓN INT

Esta ruta verifica el resultado del run `44382086626`; no reejecuta su apply.
El apply original terminó, el workflow falló en el postcheck y la retirada
administrativa tiene recibos reales. Esos resultados históricos se conservan.

`scripts/int_foundation_verify.py` reconoce únicamente el estado serial 7,
generación `1795030868572779`, lineage
`813c84a2-2ef1-ceb3-177e-3a2c3b815066` y SHA-256
`aa2d7bf8d15d0fe3fb8461483483be2aa49ccede18c94d67a1f5a5a723ef13ce`.
Comprueba 42 direcciones, ausencia de taint y lock, identidad IAP exacta,
acceso Deploy sin condición y conservación de VM, discos y sink.

La sesión administrativa habitual efectúa las lecturas actuales sin conceder
permisos. Las autorizaciones, el plan consumido y los recibos de grants y
retirada se verifican con sus fechas históricas. No se exige que continúe
vigente la ventana IAM ni se restaura la gestión temporal retirada. Se exige
que el binding temporal exacto de gestión esté ausente y que el acceso
funcional Deploy permanezca presente, conservando los demás bindings IAP.

El llamador local comprueba las fuentes contra su commit y obtiene el token
en memoria mediante el guard existente `int_vm_hostkey.GcloudUser`, cuya huella
está fijada en `ADMIN_ACTOR`. Sólo utiliza su constructor de autenticación.
Entrega ese token a `Client` mediante una función, con los metadatos del guard;
la ejecución registrada no necesita un token en variables de entorno.

El transporte admite exclusivamente las lecturas enumeradas. La única escritura
permitida crea un recibo sanitizado con `ifGenerationMatch=0` bajo
`private-plans/int/<commit de verificación>/44382086626-1/foundation-state.json`
en el bucket privado de evidencia existente. El SHA completo se recibe después
del commit; no existe autorreferencia del código a su propio commit. La ruta
rechaza otros destinos, sobrescrituras y operaciones IAM, de estado o de VM.

El recibo tiene fecha propia, identifica al verificador y enlaza el run original,
su decisión, el plan consumido, el estado serial 7 y los índices administrativos
reales. Distingue apply completado, workflow fallido, verificación posterior y
retirada verificada. No cambia el artefacto original ni convierte el run en verde.

La verificación no ejecuta Terraform, plan, apply o import. No accede al guest,
payloads de secretos o PostgreSQL y no autoriza runtime, aplicación ni Jobs.
La auditoría configurada sigue requiriendo su validación operativa separada.
