# INT: revisión SAST del código que aplica la fundación

No hay aceptación de SAST ni modificación de Bandit, sus reglas o umbrales.
La separación de etapas conserva el resultado fallido del CI de aplicación.
La fundación exige su propio inventario completo y falla ante errores, fuentes
faltantes, cambios sin revisar o hallazgos desconocidos.

Se reutilizó el reporte nativo de Bandit 1.9.4 del commit
`aa68d4a3228bf6a1092703285f05022c8727d99c`; el nuevo código de controles se
escanea separadamente sobre sus blobs exactos antes de publicarlo. Las líneas
de esta tabla identifican la evidencia original, no un reporte nuevo inventado.

| Regla / ubicación original | Severidad | Evidencia y clasificación puntual | Decisión restante |
| --- | --- | --- | --- |
| B105 `scripts/check_tf_int.py:251` | LOW | Literal público `roles/secretmanager.secretAccessor`, no contraseña. Prueba AST del valor y función; se conserva la detección. | Ninguna aceptación de credenciales; cambiar el literal o el sitio invalida la prueba. |
| B105 `scripts/check_tf_int.py:252` | LOW | Literal público `roles/secretmanager.secretVersionAdder`, con la misma prueba independiente por sitio. | Igual; no es una exclusión de B105 en ese archivo. |
| B108 `scripts/tf_int_plan.py:353` | MEDIUM | Argumento `--tmpfs` de un contenedor sin red, filesystem de solo lectura, usuario explícito, capacidades retiradas y tmpfs limitado/noexec. No crea un nombre temporal compartido del host. | Prueba estructural por sitio; no se clasifica cualquier uso de temporales como seguro. |
| B108 `scripts/tf_int_plan.py:359` | MEDIUM | Segundo tmpfs, comprobado individualmente con los mismos límites. | Mismo límite; una ruta compartida o quitar aislamiento vuelve a bloquear. |
| B404 `scripts/int_release.py:14` | LOW | El módulo sólo usa `subprocess.SubprocessError` para capturar fallos; el AST comprueba que no lanza procesos ni pasa el módulo a otro código. | El lanzamiento real delegado se revisa abajo; no queda cubierto por esta prueba. |
| B404 `scripts/tf_int_plan.py:16` | LOW | Importa subprocess y sí lanza Docker/Terraform en el runner. | **Pendiente: F-SAST-EXEC**, exclusivamente este sitio y fuente exacta. |
| B603 `scripts/tf_int_plan.py:169` | LOW | Lista argv sin shell, timeout y salida privada; rechaza `TF_VAR_*`, `TF_CLI_ARGS*`, `TF_LOG*`; las operaciones construyen comandos de herramientas fijadas y validan inputs. | **Pendiente: F-SAST-EXEC**, confianza en ejecutables/plugins y argv; no se considera resuelto sólo por usar `shell=False`. |
| B603 `scripts/tf_int_plan.py:180` | LOW | Resuelve Terraform mediante PATH y comprueba versión 1.15.8; instalación por acción oficial fijada. | **Pendiente: F-SAST-EXEC**; la versión por sí sola no autentica todo ejecutable que aparezca en PATH. |

La [documentación oficial de B603](https://bandit.readthedocs.io/en/latest/plugins/b603_subprocess_without_shell_equals_true.html)
requiere revisar las entradas incluso sin shell; B404 es una advertencia sobre
el [uso del módulo](https://bandit.readthedocs.io/en/latest/blacklists/blacklist_imports.html#b404-import-subprocess).
Estas pruebas no cambian los resultados nativos, no usan `nosec`, allowlists,
supresiones o `continue-on-error`, y no se aplican al código de aplicación.

El nuevo checker contiene además un literal de tmpfs, que se registra si Bandit
lo detecta: su prueba es específica de su lista Docker, flags de aislamiento,
usuario y tamaño. Cada observación se correlaciona con línea **y columnas AST**;
un literal seguro en la misma línea no clasifica otro hallazgo. Las regresiones
rechazan quitar aislamiento, aumentar el tmpfs, añadir `--privileged`, cambiar
el valor público y reasignar `subprocess.SubprocessError` a una función.

`F-SAST-EXEC` es la única decisión SAST residual propuesta para el apply de
fundación: **tres LOW**, no todos los findings presentes o futuros. Responsable
propuesto: AldemaroCruz; vigencia máxima propuesta hasta el 27 de noviembre de
2026 a las 23:59:59 de Guatemala, siempre limitada además por las **24 horas del
plan concreto**. Está **pendiente y bloqueante**, sin aceptación registrada.
Una eventual decisión debe nombrar esos tres fingerprints y hashes de fuentes,
el commit de controles, el commit y SHA del binario, inputs, backend y su plazo;
no habilita aplicación, imagen, Jobs ni otros SAST/HIGH/CRITICAL.

Los procedimientos posteriores `int_bootstrap_db.py`, `int_bootstrap_vm.py` e
`int_secrets.py` tenían nueve alertas propias en el reporte reutilizado. Sus
gates siguen vigentes: no se ejecutan al aplicar las 42 direcciones. El script
de arranque **sí** se evalúa en fundación: instala paquetes como root mediante
APT firmado, deja PostgreSQL enmascarado, sin clúster, y no inicializa disco,
lee secretos ni ejecuta SQL. Esto no sustituye la comprobación del SO/paquetes
de la VM real, TLS, backups/restauración ni la revisión posterior de esos nueve
sitios antes de bootstrap. No se trasladan a la VM los resultados de PostgreSQL
de CI o del runtime multimedia.
