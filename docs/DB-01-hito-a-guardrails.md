# Hito A · admisión de Noble y conciliación de SQL personal

## Bootstrap y versiones de secretos

El job protegido comprueba la decisión, la evidencia y la proyección del runner antes de entregar los inputs protegidos. Bootstrap entrega las cinco entradas TLS y PostgreSQL al paso siguiente. Secrets verifica además la procedencia del ZIP nativo de bootstrap y la huella de su CA antes de validar las cuatro entradas. Los operadores vuelven a medir la proyección en el mismo job y boot antes del intercambio WIF previsto y de los efectos. Un fallo de admisión impide tanto la evaluación de las referencias de secretos en los `env` de esos pasos como su ejecución. Las operaciones SQL personales sólo entregan la contraseña a `personal_activate` tras el segundo preflight del host y la autenticación Deploy. [Bootstrap](../.github/workflows/int-db01-noble-bootstrap.yml) · [Secrets](../.github/workflows/int-demo-a-secrets.yml) · [Intervención](../.github/workflows/int-db01-noble-intervention.yml)

La frontera protege los inputs de los procesos y el intercambio WIF que realiza el workflow. El contexto del entorno `int` y el permiso `id-token: write` pertenecen al job en GitHub Actions. El orden de pasos no protege ese contexto frente a un runner comprometido. [Orden de evaluación de los pasos](https://raw.githubusercontent.com/actions/runner/v2.338.2/src/Runner.Worker/StepsRunner.cs) · [OIDC de GitHub Actions](https://docs.github.com/en/actions/reference/security/oidc#methods-for-requesting-the-oidc-token)

## Admisión específica de DB

La revisión vincula el kernel activo, sus paquetes y las herramientas efectivas al SHA de controles y a cada operación. APT, kmod, bootstrap y Secrets requieren informes nativos vigentes, disposiciones individuales por hallazgo y coincidencia con el runner efectivo. La proyección DB conserva sus umbrales y no aplica el mínimo fijo OCI. El entorno sigue usando el gate global por defecto. La elección protegida del modo específico de cada operación requiere su propia decisión. Las seis políticas IAM de `before_bootstrap` conservan su perfil canónico y su comparación completa con etags. Su recibo habilita los preflights de permisos, que son independientes de la admisión del runner. [Admisión DB](../scripts/int_demo_a_db_runner.py) · [Gate](../scripts/check_int_demo_a.py) · [Operador IAM](../scripts/int_demo_a_iam.py)

## SQL personal

Si el rol se activó pero falla la respuesta o la limpieza, la conciliación conserva la intención y el resultado parcial. La observación exige el marcador de la activación en el destino exacto y la ausencia de la clave OS Login propia de la operación original. Una decisión de revocación posterior puede usar ese recibo de observación con las referencias originales. La activación original conserva su resultado, incluso si quedó indeterminado. El procedimiento pertenece a la aceptación independiente de SQL desde Windows. [Operador SQL personal](../scripts/int_noble_personal_sql.py) · [Contrato de recibos](../scripts/int_noble_personal_sql_contract.py)

## Publicación y demo

La observación `45268504831` conserva la admisión negativa para el kernel AWS `7.0.0-1014.14~24.04.1`. `modules_disabled=1` sería una barrera para nuevas cargas en todo el host hasta terminar el boot. La observación registró `0` y no acredita ausencia de cargas en curso ni compatibilidad en un boot bloqueado. El mínimo OCI y los demás controles siguen vigentes. [Run conservado](https://github.com/AldemaroCruz/ClipForge/actions/runs/45268504831) · [Sysctl de Linux](https://docs.kernel.org/admin-guide/sysctl/kernel.html#modules-disabled) · [Gate del host OCI](../scripts/int_demo_a_publication_host.py)

Los recibos reales de Noble y OCI son precondiciones de la secuencia posterior. `protected_runtime` debe demostrar cinco altas y 53 `no-op`. Tras su apply aprobado, la conciliación de 58 direcciones y el binding técnico de IAP web, `human_access` debe demostrar una alta y 58 `no-op`. Los dos planes y sus applies tienen custodia, locking y aprobación manual separados. Luego se verifican los Jobs y la URL HTTPS bajo IAP. [Planes y Jobs](DB-01-noble-jobs.md)
