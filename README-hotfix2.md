# ClipForge v0.4.2 — PowerShell/Python hotfix 2

Parche acumulativo sobre v0.4.2 + hotfix 1. La aplicación sigue siendo 0.4.2.
No contiene datos, modelos, secretos ni archivos de fuentes tipográficas.

## Qué corrige

`Prepare-Upgrade.ps1` ejecutaba `python scripts/check_idle.py` con cwd `/tools`.
En esa modalidad, Python incorpora `/tools/scripts` a sys.path, no su directorio
padre. El código `app` está montado en `/tools/app`, por lo que el import fallaba.

Los contenedores auxiliares ahora reciben `PYTHONPATH=/tools` y
`PYTHONDONTWRITEBYTECODE=1` explícitamente. No se modifica el entorno de Windows,
ni el contenedor principal, ni la imagen base, ni se instala ningún paquete.
Se conservan `--network none`, los montajes de solo lectura para la comprobación
y las correcciones de `${RelDir}` y `$HuggingFaceHome` del hotfix 1.

El helper verifica que app.backup y app.lease proceden del proyecto montado, no
accidentalmente del código antiguo de la imagen. `--data` es opcional para los
tests; el uso normal sigue examinando `/data`.

## Instalar

Copia el contenido de `scripts/` de este ZIP dentro de la carpeta `scripts/`
del proyecto y acepta reemplazar:

- Prepare-Upgrade.ps1
- check_idle.py
- Test-PowerShellScripts.ps1 (sin cambios desde hotfix 1; incluido por completitud)

Opcionalmente copia tests/test_upgrade_imports.py a tests/ para conservar la
regresión en el repositorio. No hace falta copiar evidence/ para ejecutar el parche.
No reemplaces data/, cache/, .env.ai, release/ ni backups/.

No ejecutes `docker compose down`, ni rebuild, ni instales un paquete llamado app.
El fallo reportado se produce antes de la parada del servicio y del respaldo.
La preparación anterior pudo haber creado directorios vacíos release/ o backups/;
no necesitan borrarse y no se consideran una preparación completada.

## Comprobación gradual

Desde PowerShell en la carpeta del proyecto, tras revisar los archivos:

```powershell
Unblock-File -LiteralPath .\scripts\Prepare-Upgrade.ps1 -ErrorAction Stop
Unblock-File -LiteralPath .\scripts\Test-PowerShellScripts.ps1 -ErrorAction Stop
.\scripts\Test-PowerShellScripts.ps1
```

Si termina con `Validacion estatica OK: 9 scripts`, ejecuta:

```powershell
.\scripts\Prepare-Upgrade.ps1 -CheckOnly
```

Resultado esperado: `Upgrade imports OK`, seguido de `No active persisted...` y
`Preflight OK`. La opción no detiene el servicio ni crea el directorio de release,
un backup o el overlay. Sí consulta Docker, /health en localhost, y copia/ejecuta/
elimina el helper de configuración allowlisted en /tmp del contenedor existente,
como el procedimiento anterior. No usa el proveedor de IA ni imprime credenciales.
Tener la app en reposo es necesario: no inicies trabajo mientras se prepara.

Solo tras pasar esa prueba, ejecuta en una instrucción separada:

```powershell
.\scripts\Prepare-Upgrade.ps1
```

Solo tras `Preparacion completada`, ejecuta:

```powershell
.\scripts\Start-Release.ps1
```

Cuando el inicio termine sin errores, comprueba:

```powershell
Invoke-RestMethod http://127.0.0.1:8080/health
```

Debe mostrar version 0.4.2. Si una etapa falla, no continúes con la siguiente.
`-CheckOnly` no valida la captura del modelo, el backup ni el build; estos pasos
ocurren en la preparación/inicio normales y siguen comprobando sus propias salidas.

## Regresión opcional

En un entorno Python del repositorio (no es necesario instalar Python en Windows
para usar los scripts de actualización):

```text
python -m unittest discover -s tests -p test_upgrade_imports.py -v
```

Consulta VALIDACION-hotfix2.md para los resultados y límites exactos.
