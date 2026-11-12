# ENV-01: DEV e INT locales persistentes

Laboratorio local autorizado el 12 de noviembre de 2026. Presupuesto nuevo cero.
Las instalaciones operativa y candidatas anteriores se conservan. La preparación
funcional se registra por separado del gate de seguridad, que continúa bloqueado;
no hay release, cloud, aceptación de riesgos ni equivalencia con un artefacto CI.

Desde PowerShell en la carpeta de este repositorio, con Docker Desktop Linux:

```powershell
$dev = "$env:LOCALAPPDATA\ClipForge\environments\dev"
$int = "$env:LOCALAPPDATA\ClipForge\environments\int"
python scripts/dev_local.py prepare --environment dev --local-http
python scripts/dev_local.py prepare --environment int --local-http
python scripts/dev_local.py build --environment dev --browser
python scripts/dev_local.py up --environment dev
```

`prepare` solo crea una ruta nueva. Conserva un puerto libre en loopback y genera
credenciales independientes; PostgreSQL no publica puertos. `status` muestra la
URL exacta, revisión, manifiesto e imagen de cada ambiente. No usar Compose
operativo ni copiar `.env`. Construir requiere las fuentes del contexto revisadas
y comprometidas en Git. El contexto se prepara y verifica con los helpers de CI.

Para el alta inicial y la aceptación completa, ejecutar en una terminal local
interactiva; las contraseñas se piden sin eco, confirmación incluida, y solo viajan
por memoria y pipe anónimo al contenedor identificado. Elegir claves distintas.
Las cuentas `qa_env01_*` son sintéticas y no son credenciales de operación.

```powershell
$run = "$env:LOCALAPPDATA\ClipForge\env01-acceptance-$(Get-Date -Format yyyyMMdd-HHmmss)"
python scripts/accept_env_local.py --dev-state $dev --int-state $int --bootstrap-admins --promote --dev-username dev_admin --int-username int_admin --report "$run\acceptance.json" --backup-destination "$run\snapshot" --restore-state "$run\restore-lab"
```

El recorrido valida DEV con autenticación, recuperación, auditoría, FFmpeg y
descarga reales; registra la validación y promueve exactamente ese ImageID a INT
sin reconstruir. Después crea el administrador de INT y comprueba ambos ambientes,
persistencia, aislamiento y restauración independiente. Las claves no quedan en
informes, argv, variables de entorno ni archivos. Para repetir con administradores
existentes, omitir `--bootstrap-admins` y usar un `$run` nuevo.

Operación diaria (sustituir `dev` por `int` para el otro ambiente):

```powershell
python scripts/dev_local.py status --environment dev
python scripts/dev_local.py down --environment dev
python scripts/dev_local.py up --environment dev
python scripts/dev_local.py restart --environment dev
```

`down` conserva volúmenes, credenciales, puertos e imágenes; solo afecta su
proyecto. Una colisión de puerto falla y no detiene servicios ajenos. Los nombres
de las cuatro cookies incluyen `dev` o `int`; origen exacto y CSRF se mantienen.
Para comenzar, usar dos perfiles separados de navegador: «ClipForge DEV» y
«ClipForge INT», cada uno con su URL exacta. HTTP requiere el perfil local
explícito; fuera de él el predeterminado sigue siendo HTTPS/Secure. La banda
superior muestra DEV/INT y la revisión. No hay montaje de código ni hot reload.

Para una candidata posterior: revisar y versionar fuentes, `build` y `up` en DEV;
validar con el recorrido `--candidate-state $dev --dev-username dev_admin --report
<informe-nuevo.json>`, registrar con `dev_local.py validate --environment dev
--report <informe-nuevo.json>`, y promover explícitamente:

```powershell
python scripts/dev_local.py promote --environment int --source-state $dev
python scripts/dev_local.py up --environment int
```

Las imágenes y contextos anteriores quedan retenidos. `rollback --environment
int` solo selecciona la imagen anterior si su revisión de esquema coincide con
la base actual; requiere `up` después. No ejecuta downgrade de DDL.

Respaldo privado y restauración a una ruta nueva desechable:

```powershell
python scripts/dev_local.py backup --environment int --destination "$run\snapshot-extra"
python scripts/dev_local.py restore --backup "$run\snapshot-extra" --state "$run\restore-extra" --local-http
python scripts/dev_local.py down --state "$run\restore-extra"
```

No iniciar trabajo durante el respaldo. Se rechazan estados activos, se detiene
la aplicación y se capturan PostgreSQL y archivos sin escritores; se vuelve a
iniciar si estaba funcionando. El dump contiene datos privados de cuentas y
hashes, pero no las claves de conexión generadas. Se verifican hashes antes de
restaurar y se crean credenciales/red/volúmenes propios. Nunca restaurar sobre
DEV, INT ni instalaciones conservadas. No publicar snapshots ni estado privado.
La restauración del recorrido queda detenida, con sus recursos retenidos para
revisión. No se promete recuperar renders interrumpidos. Whisper/LLM no forman
parte de esta aceptación; worker persistente y SEC-05 siguen pendientes.

El resumen privado de la ejecución contiene URLs, commit, manifiesto, ImageID,
revisión de migración y resultados reales. El run del nuevo SHA en GitHub se
informa al cierre; usa recursos efímeros independientes de este INT persistente.
